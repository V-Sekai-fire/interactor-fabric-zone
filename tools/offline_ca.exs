# SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
# SPDX-License-Identifier: MIT
# The offline root's seed, sealed to a key this desk's own OS holds and fed to fz_offline_ca, and FoundationDB
# TLS on localhost that trusts only that root. `elixir tools/offline_ca.exs --help` lists the verbs.

defmodule Hpke do
  @moduledoc false
  @kem <<"KEM", 0x0010::16>>
  @aeads %{aes_128_gcm: {1, 16}, aes_256_gcm: {2, 32}}

  def setup(shared, info, aead) do
    {id, nk} = Map.fetch!(@aeads, aead)
    sid = <<"HPKE", 0x0010::16, 0x0001::16, id::16>>

    context =
      <<0>> <>
        labeled_extract(sid, "", "psk_id_hash", "") <> labeled_extract(sid, "", "info_hash", info)

    secret = labeled_extract(sid, shared, "secret", "")

    %{
      key: labeled_expand(sid, secret, "key", context, nk),
      base_nonce: labeled_expand(sid, secret, "base_nonce", context, 12)
    }
  end

  def shared_secret(dh, enc, pk_r) do
    prk = labeled_extract(@kem, "", "eae_prk", dh)
    labeled_expand(@kem, prk, "shared_secret", enc <> pk_r, 32)
  end

  def encap(pk_r, sk_e \\ nil) do
    {enc, sk_e} =
      if sk_e,
        do: :crypto.generate_key(:ecdh, :prime256v1, sk_e),
        else: :crypto.generate_key(:ecdh, :prime256v1)

    {enc, shared_secret(:crypto.compute_key(:ecdh, pk_r, sk_e, :prime256v1), enc, pk_r)}
  end

  def seal(pk_r, info, plaintext, aead \\ :aes_256_gcm) do
    {enc, shared} = encap(pk_r)
    %{key: key, base_nonce: nonce} = setup(shared, info, aead)
    {ct, tag} = :crypto.crypto_one_time_aead(aead, key, nonce, plaintext, "", true)
    enc <> ct <> tag
  end

  def open_with_z(z, pk_r, info, envelope, aead \\ :aes_256_gcm)

  def open_with_z(z, pk_r, info, envelope, aead) when byte_size(envelope) >= 65 + 16 do
    enc = binary_part(envelope, 0, 65)
    body = binary_part(envelope, 65, byte_size(envelope) - 65)
    ct = binary_part(body, 0, byte_size(body) - 16)
    tag = binary_part(body, byte_size(body) - 16, 16)
    %{key: key, base_nonce: nonce} = setup(shared_secret(z, enc, pk_r), info, aead)

    case :crypto.crypto_one_time_aead(aead, key, nonce, ct, "", tag, false) do
      plain when is_binary(plain) -> {:ok, plain}
      _ -> :error
    end
  end

  def open_with_z(_, _, _, _, _), do: :error

  defp labeled_extract(sid, salt, label, ikm),
    do: :crypto.mac(:hmac, :sha256, salt, "HPKE-v1" <> sid <> label <> ikm)

  defp labeled_expand(sid, prk, label, info, len),
    do: expand(prk, <<len::16>> <> "HPKE-v1" <> sid <> label <> info, len, <<>>, <<>>, 1)

  defp expand(_prk, _info, len, _t, acc, _i) when byte_size(acc) >= len,
    do: binary_part(acc, 0, len)

  defp expand(prk, info, len, t, acc, i) do
    t = :crypto.mac(:hmac, :sha256, prk, t <> info <> <<i>>)
    expand(prk, info, len, t, acc <> t, i + 1)
  end
end

defmodule Shamir do
  @moduledoc false
  import Bitwise
  @domain "fabric-zone offline-ca share v1"

  def split(secret) do
    pairs =
      Enum.zip(
        :binary.bin_to_list(secret),
        :binary.bin_to_list(:crypto.strong_rand_bytes(byte_size(secret)))
      )

    for x <- 1..3, do: {x, for({s, a} <- pairs, into: <<>>, do: <<bxor(s, mul(a, x))>>)}
  end

  def combine([{x1, y1}, {x2, y2}]) when x1 != x2 and byte_size(y1) == byte_size(y2) do
    d = inv(bxor(x1, x2))
    {l1, l2} = {mul(x2, d), mul(x1, d)}
    pairs = Enum.zip(:binary.bin_to_list(y1), :binary.bin_to_list(y2))
    for {a, b} <- pairs, into: <<>>, do: <<bxor(mul(a, l1), mul(b, l2))>>
  end

  def encode({x, y}) do
    groups = for <<group::binary-4 <- Base.encode32(y, padding: false) <> check(x, y)>>, do: group
    Enum.join(["FZ1", Integer.to_string(x) | groups], "-")
  end

  def decode(text) do
    case String.upcase(String.replace(text, ~r/[\s-]/, "")) do
      <<"FZ1", digit, rest::binary>> when digit in ?1..?3 and byte_size(rest) == 60 ->
        x = digit - ?0
        body = binary_part(rest, 0, 52)

        with {:ok, y} <- Base.decode32(body, padding: false),
             true <- byte_size(y) == 32 and Base.encode32(y, padding: false) == body,
             true <- binary_part(rest, 52, 8) == check(x, y) do
          {:ok, {x, y}}
        else
          _ -> {:error, "its checksum does not match, so a character is mistyped"}
        end

      _ ->
        {:error, "it is not a share (FZ1, an index 1 to 3, then 60 characters)"}
    end
  end

  defp check(x, y),
    do: Base.encode32(binary_part(:crypto.hash(:sha256, @domain <> <<x>> <> y), 0, 5))

  def mul(a, b), do: mul(a, b, 0)
  defp mul(_, 0, acc), do: acc

  defp mul(a, b, acc) do
    acc = if (b &&& 1) == 1, do: bxor(acc, a), else: acc
    a = a <<< 1
    mul(if(a > 0xFF, do: bxor(a, 0x11B), else: a), b >>> 1, acc)
  end

  def inv(a) when a in 1..255, do: Enum.reduce(1..253, a, fn _, acc -> mul(acc, a) end)
end

defmodule SealStore do
  @moduledoc false
  import Bitwise
  @info "fabric-zone offline-ca-root v1"
  @key_header "fabric-zone offline-ca key v1"
  @envelope_header "fabric-zone offline-ca envelope v1"
  @creds_name "fabric-zone.offline-ca-root"
  @creds_accept %{
    "host+tpm2" => ["ef4ac13679a9480ea7db68897f9f165d", "adbc4ca3efb64201ba881b6f2e4095ea"],
    "host" => ["55b9ed1d38594d43a8319d2ebb332ac6"]
  }
  @creds_names %{
    "5a1c6a86df9d4096b1d5a65e0862f19a" => "host",
    "55b9ed1d38594d43a8319d2ebb332ac6" => "host, user-scoped",
    "0c7cc07b117645919c4b0bea08bc20fe" => "tpm2",
    "faf7eb9341e3412ca1a436f95a29362f" => "tpm2 with a PCR public key",
    "93a894094874449090caf2fc93cab553" => "host+tpm2",
    "ef4ac13679a9480ea7db68897f9f165d" => "host+tpm2, user-scoped",
    "af4950a849134eb1a73846304ff30c05" => "host+tpm2 with a PCR public key",
    "adbc4ca3efb64201ba881b6f2e4095ea" => "host+tpm2 with a PCR public key, user-scoped",
    "058469daf6f54324800549da0f8ea2fb" => "null (no encryption)"
  }
  @oaep_md %{"sha256" => :sha256, "sha1" => :sha}

  def info, do: @info
  def creds_accept, do: @creds_accept
  def hex(bytes), do: Base.encode16(bytes, case: :lower)

  def key_path(ctx), do: Path.join(ctx.dir, "key.txt")
  def sealed_path(ctx), do: Path.join(ctx.dir, "seed.sealed")
  def root_path(ctx), do: Path.join(ctx.dir, "root.txt")
  defp soft_path(ctx), do: Path.join(ctx.dir, "soft.key")

  def refuse_if_sealed(ctx) do
    if File.exists?(sealed_path(ctx)) or File.exists?(root_path(ctx)),
      do: {:error, "#{ctx.dir} already holds a seal; it is never overwritten"},
      else: :ok
  end

  def ready(%{os: :linux}), do: with({:ok, _} <- systemd_version(), do: :ok)
  def ready(_), do: :ok

  def systemd_version do
    with exe when is_binary(exe) <- System.find_executable("systemd-creds"),
         {out, 0} <- System.cmd(exe, ["--version"], stderr_to_stdout: true),
         [_, digits] <- Regex.run(~r/^systemd (\d+)/, out),
         version when version >= 256 <- String.to_integer(digits) do
      {:ok, version}
    else
      nil ->
        {:error, "systemd-creds is not on PATH; the Linux store needs systemd 256 or later"}

      version when is_integer(version) ->
        {:error,
         "systemd-below-256: this desk has systemd #{version}, and systemd-creds --user needs 256 or later"}

      _ ->
        {:error, "systemd-creds --version printed no version"}
    end
  end

  def load_key(ctx) do
    case File.read(key_path(ctx)) do
      {:ok, text} -> with {:ok, key} <- parse_record(text, @key_header), do: matching(ctx, key)
      {:error, :enoent} -> {:error, :no_key}
      {:error, reason} -> {:error, "read #{key_path(ctx)}: #{reason}"}
    end
  end

  defp matching(ctx, %{"mechanism" => mechanism} = key) do
    allowed = %{
      macos: ["secure-enclave"],
      windows: ["tpm-pcp", "dpapi"],
      linux: ["systemd-creds"],
      software_p256: ["software-p256"],
      software_rsa: ["software-rsa"]
    }

    if mechanism in Map.get(allowed, ctx.os, []),
      do: {:ok, key},
      else: {:error, "#{key_path(ctx)} names #{mechanism}, which this desk does not hold"}
  end

  defp matching(ctx, _), do: {:error, "#{key_path(ctx)} names no mechanism"}

  def ensure_key(ctx) do
    case load_key(ctx) do
      {:error, :no_key} ->
        existed = File.dir?(ctx.dir)

        with :ok <- ensure_dir(ctx.dir),
             {:ok, key} <- make_key(ctx),
             :ok <- write_new(key_path(ctx), record(@key_header, key)) do
          {:ok, key}
        else
          error ->
            if not existed, do: File.rmdir(ctx.dir)
            error
        end

      other ->
        other
    end
  end

  defp make_key(%{os: :macos} = ctx) do
    case seal_cmd(ctx, ["create", ctx.dir] ++ if(ctx.presence, do: [], else: ["--no-presence"])) do
      {0, point} ->
        {:ok,
         %{
           "mechanism" => "secure-enclave",
           "public" => point,
           "handle" => "se.handle",
           "presence" => yes(ctx.presence)
         }}

      {3, _} ->
        {:error, "no Secure Enclave key could be made on this Mac (fz_seal create exited 3)"}

      {6, _} ->
        {:error,
         "#{Path.join(ctx.dir, "se.handle")} exists without key.txt; it is never replaced, so move it aside by hand"}

      {status, _} ->
        {:error, "fz_seal create exited #{inspect(status)}"}
    end
  end

  defp make_key(%{os: :windows} = ctx) do
    case seal_cmd(ctx, ["create", ctx.key_name]) do
      {0, blob} ->
        with {:ok, bytes} <- Base.decode16(blob, case: :mixed),
             {:ok, {e, n}} <- rsa_from_blob(bytes),
             key = %{
               "mechanism" => "tpm-pcp",
               "key-name" => ctx.key_name,
               "public" => hex(spki(e, n))
             },
             {:ok, md} <- choose_oaep(ctx, key) do
          {:ok, Map.put(key, "oaep", md)}
        else
          failure ->
            seal_cmd(ctx, ["delete-key", ctx.key_name])

            error =
              if match?({:error, _}, failure),
                do: failure,
                else: {:error, "fz_seal create printed no key blob"}

            fall_back(ctx, error)
        end

      {3, _} ->
        fall_back(ctx, {:error, "no TPM Platform Crypto Provider is usable here"})

      {6, _} ->
        {:error,
         "a TPM key named \"#{ctx.key_name}\" exists without #{key_path(ctx)}; it is never replaced (fz_seal delete-key removes a stale one)"}

      {status, _} ->
        {:error, "fz_seal create exited #{inspect(status)}"}
    end
  end

  defp make_key(%{os: :linux}) do
    binding = if File.exists?("/dev/tpmrm0"), do: "host+tpm2", else: "host"
    {:ok, %{"mechanism" => "systemd-creds", "binding" => binding, "name" => @creds_name}}
  end

  defp make_key(%{os: :software_p256} = ctx) do
    {point, scalar} = :crypto.generate_key(:ecdh, :prime256v1)

    with :ok <- write_new(soft_path(ctx), scalar),
         do: {:ok, %{"mechanism" => "software-p256", "public" => hex(point)}}
  end

  defp make_key(%{os: :software_rsa} = ctx) do
    {[e, n], private} = :crypto.generate_key(:rsa, {2048, 65537})
    key = %{"mechanism" => "software-rsa", "public" => hex(spki(e, n))}

    with :ok <- write_new(soft_path(ctx), :erlang.term_to_binary(private)),
         {:ok, md} <- choose_oaep(ctx, key),
         do: {:ok, Map.put(key, "oaep", md)}
  end

  defp fall_back(%{allow_dpapi: true}, _),
    do: {:ok, %{"mechanism" => "dpapi", "scope" => "current-user"}}

  defp fall_back(_, {:error, message}),
    do: {:error, "#{message}; --dpapi lets DPAPI (CurrentUser) hold the seed instead"}

  # SHA-256 OAEP unless the TPM refuses it; the probe takes the same path as the seed.
  defp choose_oaep(ctx, key) do
    probe = :crypto.strong_rand_bytes(32)
    {:ok, public} = from_spki(unhex!(key["public"]))

    choice =
      Enum.find(["sha256", "sha1"], fn md ->
        rsa_unwrap(ctx, key, rsa_encrypt(public, probe, md), md) == {:ok, probe}
      end)

    if choice,
      do: {:ok, choice},
      else: {:error, "the key opened neither OAEP-SHA256 nor OAEP-SHA1 ciphertext"}
  end

  def seal(ctx, key, seed) do
    case recipient_of(key) do
      {:ok, to} -> seal_to(to, seed)
      _ -> seal_in_os(ctx, key, seed)
    end
  end

  def seal_to({:p256, point}, seed), do: {:ok, Hpke.seal(point, @info, seed)}
  def seal_to({:rsa, public, md}, seed), do: {:ok, rsa_encrypt(public, seed, md)}

  defp seal_in_os(ctx, %{"mechanism" => "dpapi"}, seed) do
    case seal_cmd(ctx, ["protect"], hex(seed)) do
      {0, blob} -> Base.decode16(blob, case: :mixed)
      {status, _} -> {:error, "fz_seal protect exited #{inspect(status)}"}
    end
  end

  defp seal_in_os(_ctx, %{"mechanism" => "systemd-creds", "binding" => binding}, seed) do
    exe = System.find_executable("systemd-creds")
    # systemd-creds reads the plaintext to EOF, and an Erlang port cannot close stdin alone.
    command =
      "head -c 32 | exec '#{exe}' --user --name=#{@creds_name} --with-key=#{binding} encrypt - -"

    port =
      Port.open({:spawn_executable, "/bin/sh"}, [:binary, :exit_status, args: ["-c", command]])

    Port.command(port, seed)

    case collect(port, "", 60_000) do
      {0, text} -> with :ok <- check_creds_header(text, binding), do: {:ok, text}
      {status, _} -> {:error, "systemd-creds encrypt exited #{inspect(status)}"}
    end
  end

  def check_creds_header(text, binding) do
    with {:ok, <<id::binary-16, _::binary>>} <- Base.decode64(String.replace(text, ~r/\s/, "")),
         actual = hex(id),
         false <- actual in Map.fetch!(@creds_accept, binding) do
      {:error,
       "systemd-creds wrote a #{creds_name(actual)} credential where #{binding} was asked; nothing was stored"}
    else
      true -> :ok
      _ -> {:error, "systemd-creds printed no credential"}
    end
  end

  def creds_name(id), do: Map.get(@creds_names, id, "unknown key type #{id}")

  def open(ctx, key, sealed) do
    case open_any(ctx, key, sealed) do
      {:ok, seed} when byte_size(seed) == 32 -> {:ok, seed}
      {:ok, _} -> {:error, "the seal opened to something other than 32 bytes"}
      {:error, _} = error -> error
      _ -> {:error, "the seal in #{ctx.dir} did not open"}
    end
  end

  defp open_any(ctx, %{"mechanism" => "secure-enclave", "public" => point}, sealed) do
    with true <- byte_size(sealed) > 65 || :error,
         {0, z} <- seal_cmd(ctx, ["z", ctx.dir], hex(binary_part(sealed, 0, 65)), 300_000),
         {:ok, z} <- Base.decode16(z, case: :mixed) do
      Hpke.open_with_z(z, unhex!(point), @info, sealed)
    else
      {8, _} -> {:error, "the presence prompt was cancelled"}
      {status, _} -> {:error, "the Secure Enclave refused (fz_seal z exited #{inspect(status)})"}
      other -> other
    end
  end

  defp open_any(ctx, %{"mechanism" => "software-p256", "public" => point}, sealed) do
    with true <- byte_size(sealed) > 65 || :error,
         {:ok, scalar} <- File.read(soft_path(ctx)) do
      z = :crypto.compute_key(:ecdh, binary_part(sealed, 0, 65), scalar, :prime256v1)
      Hpke.open_with_z(z, unhex!(point), @info, sealed)
    end
  rescue
    ErlangError -> :error
  end

  defp open_any(ctx, %{"mechanism" => m, "oaep" => md} = key, sealed)
       when m in ["tpm-pcp", "software-rsa"],
       do: rsa_unwrap(ctx, key, sealed, md)

  defp open_any(ctx, %{"mechanism" => "dpapi"}, sealed) do
    case seal_cmd(ctx, ["unprotect"], hex(sealed)) do
      {0, plain} ->
        Base.decode16(plain, case: :mixed)

      {status, _} ->
        {:error, "DPAPI refused the seal (fz_seal unprotect exited #{inspect(status)})"}
    end
  end

  defp open_any(ctx, %{"mechanism" => "systemd-creds"}, _sealed) do
    args = ["--user", "--name=#{@creds_name}", "--newline=no", "decrypt", sealed_path(ctx), "-"]

    case System.cmd(System.find_executable("systemd-creds") || "systemd-creds", args) do
      {seed, 0} -> {:ok, seed}
      {_, status} -> {:error, "systemd-creds decrypt exited #{status}"}
    end
  end

  defp open_any(_ctx, %{"mechanism" => m}, _), do: {:error, "#{m} has no open"}

  defp rsa_unwrap(ctx, %{"mechanism" => "tpm-pcp", "key-name" => name}, sealed, md) do
    case seal_cmd(ctx, ["unwrap", name, md], hex(sealed)) do
      {0, plain} ->
        Base.decode16(plain, case: :mixed)

      {status, _} ->
        {:error, "the TPM refused the seal (fz_seal unwrap exited #{inspect(status)})"}
    end
  end

  defp rsa_unwrap(ctx, %{"mechanism" => "software-rsa"}, sealed, md) do
    if ctx[:refuse_sha256] && md == "sha256" do
      :error
    else
      with {:ok, stored} <- File.read(soft_path(ctx)) do
        {:ok, :crypto.private_decrypt(:rsa, sealed, :erlang.binary_to_term(stored), oaep(md))}
      end
    end
  rescue
    ErlangError -> :error
  end

  def rsa_encrypt({e, n}, plain, md), do: :crypto.public_encrypt(:rsa, plain, [e, n], oaep(md))

  defp oaep(md) do
    hash = Map.fetch!(@oaep_md, md)
    [{:rsa_padding, :rsa_pkcs1_oaep_padding}, {:rsa_oaep_md, hash}, {:rsa_mgf1_md, hash}]
  end

  def spki(e, n) do
    entry = {:RSAPublicKey, :binary.decode_unsigned(n), :binary.decode_unsigned(e)}

    {:SubjectPublicKeyInfo, der, :not_encrypted} =
      :public_key.pem_entry_encode(:SubjectPublicKeyInfo, entry)

    der
  end

  def from_spki(der) do
    case :public_key.pem_entry_decode({:SubjectPublicKeyInfo, der, :not_encrypted}) do
      {:RSAPublicKey, n, e} when n >= 1 <<< 2047 and n < 1 <<< 2048 ->
        {:ok, {:binary.encode_unsigned(e), :binary.encode_unsigned(n)}}

      _ ->
        {:error, "not the SubjectPublicKeyInfo of a 2048-bit RSA key"}
    end
  rescue
    _ -> {:error, "not a SubjectPublicKeyInfo"}
  end

  def rsa_blob(e, n),
    do:
      <<0x31415352::little-32, 2048::little-32, byte_size(e)::little-32, byte_size(n)::little-32,
        0::64>> <> e <> n

  def rsa_from_blob(
        <<0x31415352::little-32, 2048::little-32, cb_e::little-32, 256::little-32, 0::64,
          rest::binary>>
      )
      when cb_e in 1..8 and byte_size(rest) == cb_e + 256,
      do: {:ok, {binary_part(rest, 0, cb_e), binary_part(rest, cb_e, 256)}}

  def rsa_from_blob(_), do: {:error, "not the BCRYPT_RSAPUBLIC_BLOB of a 2048-bit key"}

  def recipient(key) do
    case recipient_of(key) do
      {:ok, {:p256, point}} -> {:ok, "p256:" <> hex(point)}
      {:ok, {:rsa, _, "sha1"}} -> {:ok, "rsa-sha1:" <> key["public"]}
      {:ok, {:rsa, _, _}} -> {:ok, "rsa:" <> key["public"]}
      error -> error
    end
  end

  defp recipient_of(%{"mechanism" => m, "public" => point})
       when m in ["secure-enclave", "software-p256"],
       do: {:ok, {:p256, unhex!(point)}}

  defp recipient_of(%{"mechanism" => m, "public" => der, "oaep" => md})
       when m in ["tpm-pcp", "software-rsa"] do
    with {:ok, public} <- from_spki(unhex!(der)), do: {:ok, {:rsa, public, md}}
  end

  defp recipient_of(%{"mechanism" => m}),
    do: {:error, "#{m} holds no public key, so this desk takes the seed with recover"}

  def parse_recipient(text) do
    {kind, body} =
      case String.split(String.trim(text), ":", parts: 2) do
        [kind, body] -> {kind, String.downcase(body)}
        _ -> {nil, ""}
      end

    with {:ok, bytes} <- Base.decode16(body, case: :lower),
         {:ok, to} <- recipient_key(kind, bytes) do
      {:ok, kind <> ":" <> body, to}
    else
      {:error, _} = error -> error
      :error -> {:error, "RECIPIENT is p256:<hex>, rsa:<hex> or rsa-sha1:<hex>"}
    end
  end

  defp recipient_key("p256", <<4, _::binary-64>> = point) do
    {_, scalar} = :crypto.generate_key(:ecdh, :prime256v1)
    _ = :crypto.compute_key(:ecdh, point, scalar, :prime256v1)
    {:ok, {:p256, point}}
  rescue
    ErlangError -> {:error, "the p256 RECIPIENT is not a point on P-256"}
  end

  defp recipient_key("rsa", der),
    do: with({:ok, public} <- from_spki(der), do: {:ok, {:rsa, public, "sha256"}})

  defp recipient_key("rsa-sha1", der),
    do: with({:ok, public} <- from_spki(der), do: {:ok, {:rsa, public, "sha1"}})

  defp recipient_key(_, _), do: :error

  def envelope(to, sealed), do: record(@envelope_header, %{"to" => to, "sealed" => hex(sealed)})

  def read_envelope(path) do
    with {:ok, text} <- File.read(path),
         {:ok, %{"to" => to, "sealed" => sealed}} <- parse_record(text, @envelope_header),
         {:ok, bytes} <- Base.decode16(sealed, case: :mixed) do
      {:ok, to, bytes}
    else
      {:error, reason} when is_atom(reason) -> {:error, "read #{path}: #{reason}"}
      _ -> {:error, "#{path} is not an offline-ca envelope"}
    end
  end

  def describe(ctx, key) do
    case key do
      %{"mechanism" => "secure-enclave", "presence" => presence} ->
        "secure-enclave: a non-permanent Secure Enclave P-256 key, handle se.handle, user presence " <>
          if(presence == "yes", do: "required", else: "not required (a test store)")

      %{"mechanism" => "tpm-pcp", "key-name" => name, "oaep" => md} ->
        "tpm-pcp: the RSA-2048 key \"#{name}\" on the Microsoft Platform Crypto Provider, RSA-OAEP-#{String.upcase(md)}"

      %{"mechanism" => "dpapi"} ->
        "dpapi: CryptProtectData in the CurrentUser scope; no TPM Platform Crypto Provider was usable when it was made"

      %{"mechanism" => "systemd-creds", "binding" => binding} ->
        written =
          with {:ok, text} <- File.read(sealed_path(ctx)),
               {:ok, <<id::binary-16, _::binary>>} <-
                 Base.decode64(String.replace(text, ~r/\s/, "")) do
            ", credential key #{creds_name(hex(id))}"
          else
            _ -> ""
          end

        "systemd-creds: --user credential #{@creds_name}, asked for #{binding}#{written}"

      %{"mechanism" => "software-rsa", "oaep" => md} ->
        "software-rsa: a software RSA-2048 key for the self-test, RSA-OAEP-#{String.upcase(md)}"

      %{"mechanism" => m} ->
        "#{m}: a software key for the self-test, not an OS store"
    end
  end

  def legacy_reader(%{os: :windows} = ctx, opts) do
    target = opts[:legacy_target] || "offline-ca-root.weftspun.fabric-zone"

    fn ->
      case Regex.match?(~r/\A[\x20-\x7e]+\z/, target) && seal_cmd(ctx, ["legacy-read", target]) do
        false ->
          {:error, "--legacy-target is printable ASCII"}

        {0, blob} ->
          with {:ok, bytes} <- Base.decode16(blob, case: :mixed), do: {:ok, {:utf16le, bytes}}

        {7, _} ->
          {:error, "no generic credential #{target}"}

        {status, _} ->
          {:error, "fz_seal legacy-read exited #{inspect(status)}"}
      end
    end
  end

  def legacy_reader(%{os: :macos}, opts) do
    keychain = if opts[:legacy_keychain], do: [Path.expand(opts[:legacy_keychain])], else: []

    args =
      ["find-generic-password", "-s", "weftspun.fabric-zone", "-a", "offline-ca-root", "-w"] ++
        keychain

    fn ->
      case System.cmd("/usr/bin/security", args) do
        {out, 0} -> {:ok, {:utf8, String.trim_trailing(out, "\n")}}
        {_, 44} -> {:error, "no generic password weftspun.fabric-zone / offline-ca-root"}
        {_, status} -> {:error, "security find-generic-password exited #{status}"}
      end
    end
  end

  def legacy_reader(_, _),
    do: fn -> {:error, "adopt reads the old keyring entry on Windows and macOS"} end

  # keyring 3.6.3 stores a password on Windows as UTF-16LE with no terminator, and on macOS as UTF-8.
  def decode_legacy({:utf16le, bytes}) when rem(byte_size(bytes), 2) == 0 do
    case :unicode.characters_to_binary(bytes, {:utf16, :little}) do
      text when is_binary(text) -> decode_legacy({:utf8, text})
      _ -> {:error, "the legacy entry is not UTF-16LE"}
    end
  end

  def decode_legacy({:utf16le, _}),
    do: {:error, "the legacy entry has an odd length, so it is not UTF-16LE"}

  def decode_legacy({:utf8, text}) do
    case Base.decode64(text) do
      {:ok, seed} when byte_size(seed) == 32 -> {:ok, seed}
      _ -> {:error, "the legacy entry is not the Base64 of 32 bytes"}
    end
  end

  def seal_and_write(ctx, key, seed, root) do
    with {:ok, sealed} <- seal(ctx, key, seed),
         :ok <- write_new(sealed_path(ctx), sealed),
         do: write_new(root_path(ctx), root <> "\n")
  end

  # Written beside the target, flushed, then hard-linked in, so an existing file is never replaced.
  def write_new(path, data) do
    temporary = "#{path}.#{System.unique_integer([:positive])}.tmp"

    result =
      with {:ok, fd} <- :file.open(temporary, [:write, :binary, :raw, :exclusive]) do
        written =
          with :ok <- restrict(temporary, 0o600), :ok <- :file.write(fd, data), do: :file.sync(fd)

        closed = :file.close(fd)
        with :ok <- written, :ok <- closed, do: :file.make_link(temporary, path)
      end

    File.rm(temporary)

    case result do
      :ok -> :ok
      {:error, :eexist} -> {:error, "#{path} exists; it is never overwritten"}
      {:error, reason} -> {:error, "write #{path}: #{inspect(reason)}"}
    end
  end

  def ensure_dir(dir) do
    with :ok <- File.mkdir_p(dir), do: restrict(dir, 0o700)
  end

  defp restrict(path, mode) do
    if match?({:win32, _}, :os.type()), do: :ok, else: File.chmod(path, mode)
  end

  def record(header, fields) do
    {mechanism, rest} = Map.pop(fields, "mechanism")
    lines = if(mechanism, do: [{"mechanism", mechanism}], else: []) ++ Enum.sort(rest)
    Enum.map_join([header | Enum.map(lines, fn {k, v} -> "#{k} #{v}" end)], "", &(&1 <> "\n"))
  end

  def parse_record(text, header) do
    case String.split(text, ~r/\r?\n/, trim: true) do
      [^header | lines] ->
        {:ok,
         Map.new(lines, fn line ->
           case String.split(line, " ", parts: 2) do
             [k, v] -> {k, v}
             [k] -> {k, ""}
           end
         end)}

      _ ->
        {:error, "not a #{header} record"}
    end
  end

  def seal_cmd(ctx, args, input \\ nil, timeout \\ 60_000) do
    port = Port.open({:spawn_executable, ctx.seal_exe}, [:binary, :exit_status, args: args])
    if input, do: Port.command(port, input <> "\n")
    collect(port, "", timeout)
  end

  def collect(port, out, timeout) do
    receive do
      {^port, {:data, data}} -> collect(port, out <> data, timeout)
      {^port, {:exit_status, status}} -> {status, String.trim(out)}
    after
      timeout -> {:timeout, out}
    end
  end

  defp unhex!(text), do: Base.decode16!(text, case: :mixed)
  defp yes(true), do: "yes"
  defp yes(_), do: "no"
end

defmodule OfflineCa do
  import Bitwise
  @suffix ".fdb.fabric.internal"
  @leaf_seconds 3600
  @root_seconds 365 * 86_400
  @fdb_port 4690
  @repo Path.expand("..", __DIR__)
  @build Path.join(@repo, "build/offline_ca")
  @default_key_name "fabric-zone offline-ca-root"
  @ikm_e "4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e"
  @pk_em "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
  @switches [
    store: :string,
    no_presence: :boolean,
    dpapi: :boolean,
    legacy_target: :string,
    legacy_keychain: :string,
    control: :string,
    self_test: :boolean,
    os_check: :boolean,
    help: :boolean
  ]
  @usage """
  usage: elixir tools/offline_ca.exs VERB [--store DIR]

    init                       a new seed sealed to this desk; prints the root and three recovery shares
    adopt ROOTHEX              seal the seed the old keyring tool stored, if it gives ROOTHEX; prints shares
    recipient                  make this desk's key if it has none and print its RECIPIENT
    enroll RECIPIENT OUT       write OUT, an envelope of this desk's seed for another desk
    install ENVELOPE ROOTHEX   seal an enrolled envelope here, if it opens to a seed that gives ROOTHEX
    recover ROOTHEX            read two shares on stdin, rebuild the seed, check ROOTHEX, seal it here
    status                     which mechanism holds the seed and where, without opening it
    public                     print the root public key
    issue LABEL DIR            write DIR/root.pem and a one-hour LABEL.fdb.fabric.internal certificate
    fdb-e2e DIR [--control=trust-other-root]
                               FoundationDB 7.3 over TLS on 127.0.0.1:4690, trusting only this root
    --self-test                the store's logic with software keys; touches no OS store
    --os-check                 this OS's store with throwaway keys, stores and credentials (CI)

    --store DIR                the store directory; by default ~/Library/Application Support/fabric-zone/
                               offline-ca on macOS, %LOCALAPPDATA%\\fabric-zone\\offline-ca on Windows, and
                               $XDG_STATE_HOME (or ~/.local/state)/fabric-zone/offline-ca on Linux
    --no-presence              macOS, with an explicit --store only: the Enclave key asks for no presence
    --dpapi                    Windows: let DPAPI (CurrentUser) hold the seed where no TPM PCP is usable
    --legacy-target TARGET     Windows adopt: the generic credential, in ASCII (offline-ca-root.weftspun.fabric-zone)
    --legacy-keychain FILE     macOS adopt: read this keychain file instead of the search list

  ROOTHEX is the root public key, 130 hex characters starting 04.
  RECIPIENT is p256:<130 hex>, a macOS desk's Enclave key as a SEC1 point, or rsa:<hex> or
  rsa-sha1:<hex>, a Windows desk's TPM key as SubjectPublicKeyInfo DER with the OAEP hash its TPM
  takes. `recipient` prints it. A Linux or DPAPI desk has no RECIPIENT and takes the seed with recover.
  """

  def main(args) do
    case run(args) do
      :ok ->
        :ok

      {:ok, lines} ->
        Enum.each(lines, &IO.puts/1)

      {:error, message} ->
        IO.puts(:stderr, "FAIL #{message}")
        System.halt(1)
    end
  end

  def run(args) do
    case OptionParser.parse(args, strict: @switches) do
      {opts, positional, []} ->
        dispatch(positional, Map.new(opts))

      {_, _, invalid} ->
        {:error, "unknown option #{Enum.map_join(invalid, ", ", &elem(&1, 0))}\n#{@usage}"}
    end
  end

  defp dispatch(_, %{help: true}), do: {:ok, [@usage]}
  defp dispatch([], %{self_test: true}), do: self_test(cli())
  defp dispatch([], %{os_check: true}), do: os_check(cli())

  defp dispatch(positional, opts) do
    with {:ok, ctx} <- store_ctx(opts), do: verb(positional, ctx, opts)
  end

  defp verb(["status"], ctx, _), do: status(ctx)
  defp verb(["init"], ctx, _), do: init(ctx, cli())
  defp verb(["adopt", roothex], ctx, _), do: adopt(ctx, cli(), roothex)
  defp verb(["recipient"], ctx, _), do: recipient(ctx, cli())
  defp verb(["enroll", to, out], ctx, _), do: enroll(ctx, cli(), to, out)
  defp verb(["install", envelope, roothex], ctx, _), do: install(ctx, cli(), envelope, roothex)
  defp verb(["recover", roothex], ctx, _), do: recover(ctx, cli(), roothex, stdin_shares([]))

  defp verb(["public"], ctx, _) do
    with {:ok, _key, _seed, root} <- open_checked(ctx, cli()), do: {:ok, [root]}
  end

  defp verb(["issue", label, dir], ctx, _), do: issue_certs(ctx, cli(), label, dir)

  defp verb(["fdb-e2e", dir], ctx, opts) do
    control = opts[:control]

    with :ok <- if(control in [nil, "trust-other-root"], do: :ok, else: {:error, @usage}),
         exe = cli(),
         {:ok, _key, seed, _root} <- open_checked(ctx, exe),
         do: fdb_e2e(exe, seed, Path.expand(dir), control != nil)
  end

  defp verb(_, _, _), do: {:error, @usage}

  def host_os do
    case :os.type() do
      {:unix, :darwin} -> :macos
      {:win32, _} -> :windows
      {:unix, :linux} -> :linux
      _ -> :other
    end
  end

  def default_dir(:macos),
    do:
      Path.join([
        System.user_home!(),
        "Library",
        "Application Support",
        "fabric-zone",
        "offline-ca"
      ])

  def default_dir(:windows),
    do: Path.join([System.fetch_env!("LOCALAPPDATA"), "fabric-zone", "offline-ca"])

  def default_dir(:linux) do
    state = System.get_env("XDG_STATE_HOME")

    base =
      if state in [nil, ""], do: Path.join([System.user_home!(), ".local", "state"]), else: state

    Path.join([base, "fabric-zone", "offline-ca"])
  end

  def default_dir(_), do: nil

  def store_ctx(opts) do
    os = host_os()
    default = default_dir(os) && Path.expand(default_dir(os))
    dir = if opts[:store], do: Path.expand(opts[:store]), else: default

    cond do
      os == :other ->
        {:error, "no OS store for #{inspect(:os.type())}"}

      opts[:no_presence] && os != :macos ->
        {:error, "--no-presence is for the macOS Secure Enclave"}

      opts[:no_presence] && (opts[:store] == nil or dir == default) ->
        {:error, "--no-presence needs an explicit --store DIR other than this desk's own store"}

      opts[:dpapi] && os != :windows ->
        {:error, "--dpapi is for Windows"}

      true ->
        ctx = %{
          dir: dir,
          os: os,
          presence: !opts[:no_presence],
          allow_dpapi: !!opts[:dpapi],
          key_name: key_name(dir, default),
          seal_exe: Path.join(@build, if(os == :windows, do: "fz_seal.exe", else: "fz_seal"))
        }

        {:ok, Map.put(ctx, :legacy, SealStore.legacy_reader(ctx, opts))}
    end
  end

  defp key_name(dir, dir), do: @default_key_name

  defp key_name(dir, _),
    do: "#{@default_key_name} #{SealStore.hex(binary_part(:crypto.hash(:sha256, dir), 0, 6))}"

  def status(ctx) do
    case SealStore.load_key(ctx) do
      {:error, :no_key} ->
        {:ok,
         ["store #{ctx.dir}", "no key and no seal yet; init, adopt, recover or install fills it"]}

      {:error, _} = error ->
        error

      {:ok, key} ->
        sealed =
          case File.stat(SealStore.sealed_path(ctx)) do
            {:ok, stat} -> "sealed #{SealStore.sealed_path(ctx)} (#{stat.size} bytes)"
            _ -> "not sealed yet"
          end

        root =
          case File.read(SealStore.root_path(ctx)) do
            {:ok, text} -> ["root #{String.trim(text)}"]
            _ -> []
          end

        to =
          case SealStore.recipient(key) do
            {:ok, text} -> ["recipient #{text}"]
            _ -> []
          end

        {:ok,
         ["store #{ctx.dir}", "mechanism #{SealStore.describe(ctx, key)}", sealed] ++ root ++ to}
    end
  end

  def init(ctx, exe) do
    seed = :crypto.strong_rand_bytes(32)

    with :ok <- SealStore.ready(ctx),
         :ok <- SealStore.refuse_if_sealed(ctx),
         {:ok, root} <- public(exe, seed),
         :ok <- install_seed(ctx, exe, seed, root) do
      {:ok, sealed_lines(ctx, root) ++ share_lines(seed)}
    end
  end

  def adopt(ctx, exe, roothex) do
    with {:ok, root} <- normalize_root(roothex),
         :ok <- SealStore.ready(ctx),
         :ok <- SealStore.refuse_if_sealed(ctx),
         {:ok, stored} <- ctx.legacy.(),
         {:ok, seed} <- SealStore.decode_legacy(stored),
         :ok <- check_root(exe, seed, root),
         :ok <- install_seed(ctx, exe, seed, root) do
      {:ok,
       sealed_lines(ctx, root) ++
         ["the legacy entry stays where it was; adopt never deletes it"] ++ share_lines(seed)}
    end
  end

  def recipient(%{os: :linux}, _exe),
    do: {:error, "systemd-creds holds no public key, so a Linux desk takes the seed with recover"}

  def recipient(ctx, _exe) do
    with :ok <- SealStore.ready(ctx),
         {:ok, key} <- SealStore.ensure_key(%{ctx | allow_dpapi: false}),
         {:ok, text} <- SealStore.recipient(key),
         do: {:ok, [text]}
  end

  def enroll(ctx, exe, to_text, out) do
    with {:ok, to_text, to} <- SealStore.parse_recipient(to_text),
         :ok <-
           if(File.exists?(out),
             do: {:error, "#{out} exists; enroll never overwrites"},
             else: :ok
           ),
         {:ok, _key, seed, root} <- open_checked(ctx, exe),
         {:ok, sealed} <- SealStore.seal_to(to, seed),
         :ok <- SealStore.write_new(out, SealStore.envelope(to_text, sealed)) do
      {:ok, ["wrote #{out} for #{short(to_text)}", "on that desk: install #{out} #{root}"]}
    end
  end

  def install(ctx, exe, path, roothex) do
    with {:ok, root} <- normalize_root(roothex),
         :ok <- SealStore.ready(ctx),
         :ok <- SealStore.refuse_if_sealed(ctx),
         {:ok, key} <-
           loaded_key(ctx, "no key in #{ctx.dir} yet; run recipient on this desk first"),
         {:ok, mine} <- SealStore.recipient(key),
         {:ok, to, sealed} <- SealStore.read_envelope(path),
         :ok <- same_recipient(path, to, mine),
         {:ok, seed} <- SealStore.open(ctx, key, sealed),
         :ok <- check_root(exe, seed, root),
         :ok <- install_seed(ctx, exe, seed, root) do
      {:ok, sealed_lines(ctx, root)}
    end
  end

  def recover(ctx, exe, roothex, lines) do
    with {:ok, root} <- normalize_root(roothex),
         :ok <- SealStore.ready(ctx),
         :ok <- SealStore.refuse_if_sealed(ctx),
         {:ok, shares} <- read_shares(lines),
         seed = Shamir.combine(shares),
         :ok <- check_root(exe, seed, root),
         :ok <- install_seed(ctx, exe, seed, root) do
      {:ok, sealed_lines(ctx, root)}
    end
  end

  def issue_certs(ctx, exe, label, dir) do
    now = System.os_time(:second) - 60
    prefix = Path.join(dir, label)

    with {:ok, _key, seed, _root} <- open_checked(ctx, exe),
         :ok <- root(exe, seed, dir, now),
         :ok <- issue(exe, seed, label <> @suffix, prefix, now, @leaf_seconds) do
      {:ok,
       [
         "wrote #{Path.join(dir, "root.pem")}, #{prefix}.key and #{prefix}.pem for #{label <> @suffix}"
       ]}
    end
  end

  defp same_recipient(_path, to, to), do: :ok

  defp same_recipient(path, to, mine),
    do:
      {:error,
       "#{path} is sealed to #{short(to)}, not to this desk (#{short(mine)}); nothing was written"}

  defp install_seed(ctx, exe, seed, root) do
    with {:ok, key} <- SealStore.ensure_key(ctx),
         :ok <- SealStore.seal_and_write(ctx, key, seed, root),
         {:ok, _key, _seed, ^root} <- open_checked(ctx, exe) do
      :ok
    else
      {:error, _} = error -> error
      _ -> {:error, "the seal in #{ctx.dir} did not open to the root #{short(root)}"}
    end
  end

  def open_checked(ctx, exe) do
    missing = "no seal in #{ctx.dir}; only init, adopt, recover or install makes one"

    with {:ok, key} <- loaded_key(ctx, missing),
         {:ok, sealed} <- read_or(SealStore.sealed_path(ctx), missing),
         {:ok, recorded} <- read_or(SealStore.root_path(ctx), missing),
         {:ok, seed} <- SealStore.open(ctx, key, sealed),
         {:ok, root} <- public(exe, seed) do
      if root == String.trim(recorded),
        do: {:ok, key, seed, root},
        else:
          {:error,
           "the seal opens to the root #{short(root)}, but root.txt records #{short(recorded)}"}
    end
  end

  defp loaded_key(ctx, missing) do
    case SealStore.load_key(ctx) do
      {:error, :no_key} -> {:error, missing}
      other -> other
    end
  end

  defp read_or(path, missing) do
    case File.read(path) do
      {:ok, data} -> {:ok, data}
      {:error, :enoent} -> {:error, missing}
      {:error, reason} -> {:error, "read #{path}: #{reason}"}
    end
  end

  defp check_root(exe, seed, expected) do
    case public(exe, seed) do
      {:ok, ^expected} ->
        :ok

      {:ok, other} ->
        {:error,
         "the seed gives the root #{short(other)}, not #{short(expected)}; nothing was written"}

      error ->
        error
    end
  end

  def normalize_root(text) do
    root = String.downcase(String.trim(text))

    if Regex.match?(~r/\A04[0-9a-f]{128}\z/, root),
      do: {:ok, root},
      else: {:error, "ROOTHEX is the root public key, 130 hex characters starting 04"}
  end

  def read_shares(lines) do
    lines = Enum.reject(lines, &(String.trim(&1) == ""))

    decoded =
      lines
      |> Enum.with_index(1)
      |> Enum.map(fn {line, i} ->
        case Shamir.decode(line) do
          {:ok, share} -> {:ok, share}
          {:error, why} -> {:error, "share #{i}: #{why}"}
        end
      end)

    case Enum.find(decoded, &match?({:error, _}, &1)) do
      nil ->
        case Enum.map(decoded, &elem(&1, 1)) do
          [{x, _}, {x, _}] ->
            {:error, "both shares carry index #{x}; two different shares are needed"}

          [_, _] = shares ->
            {:ok, shares}

          shares ->
            {:error, "two shares are needed, one per line; got #{length(shares)}"}
        end

      error ->
        error
    end
  end

  defp stdin_shares(acc) when length(acc) == 2, do: Enum.reverse(acc)

  defp stdin_shares(acc) do
    case IO.gets("") do
      line when is_binary(line) ->
        if String.trim(line) == "",
          do: stdin_shares(acc),
          else: stdin_shares([String.trim(line) | acc])

      _ ->
        Enum.reverse(acc)
    end
  end

  defp sealed_lines(ctx, root), do: ["sealed in #{ctx.dir}", "root public key #{root}"]

  defp share_lines(seed) do
    ["recovery shares (any two rebuild the seed; keep them apart):"] ++
      Enum.map(Shamir.split(seed), &Shamir.encode/1)
  end

  defp short(text),
    do:
      if(byte_size(text) > 24,
        do: binary_part(text, 0, 12) <> "..." <> binary_part(text, byte_size(text) - 4, 4),
        else: text
      )

  def cli do
    windows = host_os() == :windows
    exe = Path.join(@build, if(windows, do: "fz_offline_ca.exe", else: "fz_offline_ca"))

    unless File.exists?(Path.join(@build, "CMakeCache.txt")) do
      generator = if windows, do: ["-G", "MinGW Makefiles"], else: []

      sh!(
        "cmake",
        ["-S", @repo, "-B", @build, "-DFZ_NATIVE=ON", "-DCMAKE_BUILD_TYPE=Release"] ++ generator
      )
    end

    seal = if host_os() in [:macos, :windows], do: ["fz_seal"], else: []
    sh!("cmake", ["--build", @build, "--target", "fz_offline_ca"] ++ seal ++ ["-j", "8"])
    exe
  end

  defp sh!(cmd, args) do
    case System.cmd(cmd, args, stderr_to_stdout: true) do
      {_, 0} -> :ok
      {out, status} -> raise "#{cmd} exited #{status}:\n#{out}"
    end
  end

  defp windows?, do: host_os() == :windows

  def ca(exe, seed, args) do
    port =
      Port.open({:spawn_executable, exe}, [:binary, :exit_status, :stderr_to_stdout, args: args])

    Port.command(port, Base.encode64(seed) <> "\n")
    SealStore.collect(port, "", 30_000)
  end

  def public(exe, seed) do
    case ca(exe, seed, ["public"]) do
      {0, hex} -> {:ok, hex}
      other -> ca_result(other)
    end
  end

  def root(exe, seed, dir, not_before) do
    File.mkdir_p!(dir)

    ca_result(
      ca(exe, seed, ["root", Path.join(dir, "root.pem"), "#{not_before}", "#{@root_seconds}"])
    )
  end

  def issue(exe, seed, name, prefix, not_before, seconds) do
    File.mkdir_p!(Path.dirname(prefix))
    args = ["issue", name, prefix <> ".key", prefix <> ".pem", "#{not_before}", "#{seconds}"]
    ca_result(ca(exe, seed, args))
  end

  defp ca_result({0, _}), do: :ok

  defp ca_result({status, out}),
    do: {:error, "fz_offline_ca exited #{inspect(status)}: #{String.trim(out)}"}

  defp refused(exe, seed, name, dir, seconds, code) do
    prefix = Path.join(dir, "refused")

    {status, out} =
      ca(exe, seed, [
        "issue",
        name,
        prefix <> ".key",
        prefix <> ".pem",
        "#{System.os_time(:second)}",
        "#{seconds}"
      ])

    status == 3 and String.contains?(out, code) and not File.exists?(prefix <> ".pem")
  end

  # The control makes the server also trust the other seed's root, so that row must FAIL.
  def fdb_e2e(exe, seed, dir, trust_other) do
    with {:ok, server_bin} <- find("fdbserver"),
         {:ok, cli_bin} <- find("fdbcli"),
         :ok <- port_free(@fdb_port) do
      File.rm_rf!(dir)
      Enum.each(["data", "logs"], &File.mkdir_p!(Path.join(dir, &1)))
      now = System.os_time(:second) - 60
      other = :crypto.strong_rand_bytes(32)
      client = "local-client" <> @suffix

      prepared = [
        root(exe, seed, dir, now),
        issue(exe, seed, "local-server" <> @suffix, Path.join(dir, "server"), now, @leaf_seconds),
        issue(exe, seed, client, Path.join(dir, "client"), now, @leaf_seconds),
        issue(exe, other, client, Path.join(dir, "other-root"), now, @leaf_seconds),
        issue(
          exe,
          seed,
          client,
          Path.join(dir, "expired"),
          now - 2 * @leaf_seconds,
          @leaf_seconds
        ),
        root(exe, other, Path.join(dir, "other"), now)
      ]

      case Enum.find(prepared, &(&1 != :ok)) do
        nil ->
          File.write!(
            Path.join(dir, "fdb.cluster"),
            "fzoffline:fzoffline@127.0.0.1:#{@fdb_port}:tls\n"
          )

          if trust_other,
            do:
              File.write!(
                Path.join(dir, "root.pem"),
                File.read!(Path.join(dir, "other/root.pem")),
                [:append]
              )

          server = start_server(server_bin, dir)

          try do
            report(fdb_checks(exe, seed, cli_bin, dir))
          after
            stop(server)
          end

        error ->
          error
      end
    end
  end

  defp fdb_checks(exe, seed, cli_bin, dir) do
    created =
      fdbcli(cli_bin, dir, "client", "configure new single memory", 30) =~ "Database created"

    available =
      created and
        await(fn ->
          fdbcli(cli_bin, dir, "client", "status minimal", 5) =~ "The database is available"
        end)

    reads = fn who ->
      fdbcli(cli_bin, dir, who, "writemode on; set fz-offline ok; get fz-offline", 10) =~
        "`fz-offline' is `ok'"
    end

    rejected = fn who, error ->
      before = verify_errors(dir, error)
      not reads.(who) and await(fn -> verify_errors(dir, error) > before end)
    end

    [
      {"a :tls cluster is created with server and client certificates from the stored root",
       available},
      {"a client the stored root issued writes and reads back", reads.("client")},
      {"control: a client from another seed's root is refused (unable to get local issuer certificate)",
       rejected.("other-root", "unable to get local issuer certificate")},
      {"control: an expired client from the stored root is refused (certificate has expired)",
       rejected.("expired", "certificate has expired")},
      {"the stored root's client still reads back after the controls", reads.("client")},
      {"control: the root does not issue a .zone.fabric.internal name",
       refused(exe, seed, "local-client.zone.fabric.internal", dir, @leaf_seconds, "-100")},
      {"control: the root does not issue the Fly cluster's fdb-*.chibifire.com names",
       refused(exe, seed, "fdb-uro.chibifire.com", dir, @leaf_seconds, "-100")},
      {"control: the root does not issue past FZ_MAX_SECONDS",
       refused(exe, seed, "local-client" <> @suffix, dir, @leaf_seconds + 1, "-101")}
    ]
  end

  defp find(name) do
    case System.find_executable(name) do
      nil -> {:error, "#{name} is not on PATH; the end-to-end needs FoundationDB 7.3"}
      path -> {:ok, path}
    end
  end

  defp port_free(port) do
    case :gen_tcp.listen(port, ip: {127, 0, 0, 1}) do
      {:ok, socket} -> :gen_tcp.close(socket)
      {:error, reason} -> {:error, "127.0.0.1:#{port} is taken (#{reason})"}
    end
  end

  defp native(path), do: if(windows?(), do: String.replace(path, "/", "\\"), else: path)

  defp start_server(bin, dir) do
    at = &native(Path.join(dir, &1))

    args = [
      "-p",
      "127.0.0.1:#{@fdb_port}:tls",
      "-C",
      at.("fdb.cluster"),
      "-d",
      at.("data"),
      "-L",
      at.("logs"),
      "--tls-certificate-file",
      at.("server.pem"),
      "--tls-key-file",
      at.("server.key"),
      "--tls-ca-file",
      at.("root.pem")
    ]

    Port.open({:spawn_executable, bin}, [:binary, :exit_status, :stderr_to_stdout, args: args])
  end

  defp stop(server) do
    case Port.info(server, :os_pid) do
      {:os_pid, pid} when is_integer(pid) ->
        if windows?(),
          do: System.cmd("taskkill", ["/F", "/PID", "#{pid}"], stderr_to_stdout: true),
          else: System.cmd("kill", ["#{pid}"], stderr_to_stdout: true)

      _ ->
        :ok
    end
  end

  defp fdbcli(bin, dir, who, exec, timeout) do
    at = &native(Path.join(dir, &1))

    args = [
      "-C",
      at.("fdb.cluster"),
      "--tls-certificate-file",
      at.(who <> ".pem"),
      "--tls-key-file",
      at.(who <> ".key"),
      "--tls-ca-file",
      at.("root.pem"),
      "--timeout",
      "#{timeout}",
      "--exec",
      exec
    ]

    {out, _} = System.cmd(bin, args, stderr_to_stdout: true)
    out
  end

  defp verify_errors(dir, error) do
    Path.wildcard(Path.join([dir, "logs", "*.xml"]))
    |> Enum.map(&(length(String.split(File.read!(&1), ~s(VerifyError="#{error}"))) - 1))
    |> Enum.sum()
  end

  defp await(check, tries \\ 30) do
    cond do
      check.() -> true
      tries == 1 -> false
      true -> Process.sleep(1000) && await(check, tries - 1)
    end
  end

  defp scratch(name) do
    dir = Path.join(System.tmp_dir!(), "offline_ca_#{name}_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    dir
  end

  defp soft(base, name, os, extra \\ %{}) do
    Map.merge(
      %{
        dir: Path.join(base, name),
        os: os,
        presence: false,
        allow_dpapi: false,
        key_name: nil,
        seal_exe: nil,
        legacy: fn -> {:error, "no legacy entry in a test store"} end
      },
      extra
    )
  end

  defp snapshot(dir) do
    case File.ls(dir) do
      {:ok, names} -> Map.new(Enum.sort(names), &{&1, File.read!(Path.join(dir, &1))})
      {:error, reason} -> reason
    end
  end

  defp h(text), do: Base.decode16!(text, case: :lower)

  defp first_line({:ok, [line | _]}), do: line
  defp first_line(_), do: ""

  defp rfc9180_a31 do
    pk_rm =
      h(
        "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"
      )

    {enc, shared} =
      Hpke.encap(pk_rm, h("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb"))

    %{key: key, base_nonce: nonce} =
      Hpke.setup(shared, h("4f6465206f6e2061204772656369616e2055726e"), :aes_128_gcm)

    plain = h("4265617574792069732074727574682c20747275746820626561757479")
    {ct, tag} = :crypto.crypto_one_time_aead(:aes_128_gcm, key, nonce, plain, "Count-0", true)

    enc == h(@pk_em) and
      shared == h("c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8") and
      key == h("868c066ef58aae6dc589b6cfdd18f97e") and nonce == h("4e0bc5018beba4bf004cca59") and
      ct <> tag ==
        h(
          "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434"
        )
  end

  defp flip(bytes, at) do
    rest = binary_part(bytes, at + 1, byte_size(bytes) - at - 1)
    binary_part(bytes, 0, at) <> <<bxor(:binary.at(bytes, at), 1)>> <> rest
  end

  defp creds_header(id_hex) do
    Base.encode64(h(id_hex) <> :crypto.strong_rand_bytes(160))
    |> String.graphemes()
    |> Enum.chunk_every(79)
    |> Enum.map_join("\n", &Enum.join/1)
  end

  def self_test(exe) do
    base = scratch("self_test")

    try do
      report(self_test_rows(exe, base))
    after
      File.rm_rf!(base)
    end
  end

  defp self_test_rows(exe, base) do
    kat = h(@ikm_e)
    flipped = flip(kat, 0)
    other_root = with({:ok, hex} <- public(exe, flipped), do: hex, else: (_ -> @pk_em))
    info = SealStore.info()

    empty = soft(base, "empty", :software_p256)
    out = Path.join(base, "issue-out")
    File.mkdir_p!(out)
    no_seed = issue_certs(empty, exe, "local-client", out)
    nothing_written = File.ls!(out) == [] and not File.exists?(empty.dir)

    a = soft(base, "a", :software_p256)
    first_init = init(a, exe)
    kept = snapshot(a.dir)
    second_init = init(a, exe)

    {seed, root} =
      with(
        {:ok, _, seed, root} <- open_checked(a, exe),
        do: {seed, root},
        else: (_ -> {<<0::256>>, ""})
      )

    shares =
      for {:ok, lines} <- [first_init], line <- lines, String.starts_with?(line, "FZ1-"), do: line

    {pk_r, sk_r} = :crypto.generate_key(:ecdh, :prime256v1)
    {_, sk_other} = :crypto.generate_key(:ecdh, :prime256v1)
    envelope = Hpke.seal(pk_r, info, seed)
    z = fn env, sk -> :crypto.compute_key(:ecdh, binary_part(env, 0, 65), sk, :prime256v1) end

    pairs = for i <- 0..1, j <- (i + 1)..2, do: [Enum.at(shares, i), Enum.at(shares, j)]
    rebuilt = Enum.map(pairs, &with({:ok, s} <- read_shares(&1), do: Shamir.combine(s)))
    [first_share | _] = shares
    <<head::binary-8, char, tail::binary>> = first_share
    typo = head <> <<if(char == ?A, do: ?B, else: ?A)>> <> tail

    r = soft(base, "recover", :software_rsa)
    recovered = recover(r, exe, root, Enum.take(shares, 2))
    rw = soft(base, "recover-wrong", :software_p256)
    recover_wrong = recover(rw, exe, other_root, Enum.drop(shares, 1))

    b = soft(base, "b", :software_p256)
    to_b = first_line(recipient(b, exe))
    envelope_b = Path.join(base, "b.envelope")
    enrolled = enroll(a, exe, to_b, envelope_b)
    installed = install(b, exe, envelope_b, root)

    c = soft(base, "c", :software_rsa)
    to_c = first_line(recipient(c, exe))
    envelope_c = Path.join(base, "c.envelope")
    enroll(a, exe, to_c, envelope_c)
    before_c = snapshot(c.dir)
    install_wrong = install(c, exe, envelope_c, other_root)
    after_c = snapshot(c.dir)
    install_c = install(c, exe, envelope_c, root)

    d = soft(base, "d", :software_p256)
    recipient(d, exe)
    before_d = snapshot(d.dir)
    install_other = install(d, exe, envelope_b, root)

    e = soft(base, "e", :software_rsa, %{refuse_sha256: true})
    to_e = first_line(recipient(e, exe))
    envelope_e = Path.join(base, "e.envelope")
    enroll(a, exe, to_e, envelope_e)
    install_e = install(e, exe, envelope_e, root)
    status_e = with({:ok, lines} <- status(e), do: lines, else: (_ -> []))

    legacy = :unicode.characters_to_binary(Base.encode64(seed), :utf8, {:utf16, :little})
    from_legacy = %{legacy: fn -> {:ok, {:utf16le, legacy}} end}
    ad = soft(base, "adopt", :software_p256, from_legacy)
    adopted = adopt(ad, exe, root)
    aw = soft(base, "adopt-wrong", :software_p256, from_legacy)
    adopt_wrong = adopt(aw, exe, other_root)

    utf8 =
      soft(base, "adopt-utf8", :software_p256, %{
        legacy: fn -> {:ok, {:utf16le, Base.encode64(seed)}} end
      })

    adopt_utf8 = adopt(utf8, exe, root)

    [host_tpm, _] = SealStore.creds_accept()["host+tpm2"]
    [host] = SealStore.creds_accept()["host"]
    {[rsa_e, rsa_n], _} = :crypto.generate_key(:rsa, {2048, 65537})
    blob = SealStore.rsa_blob(rsa_e, rsa_n)

    [
      {"RFC 9180 A.3 through fz_offline_ca: ikmE gives pkEm", public(exe, kat) == {:ok, @pk_em}},
      {"control: one flipped seed bit gives another root", other_root != @pk_em},
      {"control: a 31-byte seed is refused",
       match?({2, _}, ca(exe, binary_part(kat, 0, 31), ["public"]))},
      {"control: with no stored seed, issue refuses and writes nothing",
       match?({:error, _}, no_seed) and nothing_written},
      {"init stores a seed that derives a root, and prints it with three shares",
       match?({:ok, _}, first_init) and length(shares) == 3 and
         Enum.member?(elem(first_init, 1), "root public key #{root}")},
      {"control: a second init refuses and keeps the first seal",
       match?({:error, _}, second_init) and snapshot(a.dir) == kept},
      {"the stored seed gives the same root on every run",
       match?({:ok, _, ^seed, ^root}, open_checked(a, exe)) and public(exe, seed) == {:ok, root}},
      {"Elixir HPKE reproduces RFC 9180 A.3.1: enc, shared secret, key, base nonce, first ciphertext",
       rfc9180_a31()},
      {"HPKE with AES-256-GCM: an envelope to a P-256 key opens with that key's Z",
       Hpke.open_with_z(z.(envelope, sk_r), pk_r, info, envelope) == {:ok, seed}},
      {"control: another recipient's key is refused",
       Hpke.open_with_z(z.(envelope, sk_other), pk_r, info, envelope) == :error},
      {"control: a flipped envelope bit is refused",
       Hpke.open_with_z(z.(envelope, sk_r), pk_r, info, flip(envelope, 80)) == :error},
      {"control: a wrong info string is refused",
       Hpke.open_with_z(z.(envelope, sk_r), pk_r, "fabric-zone offline-ca-root v2", envelope) ==
         :error},
      {"control: a truncated tag is refused",
       Hpke.open_with_z(
         z.(envelope, sk_r),
         pk_r,
         info,
         binary_part(envelope, 0, byte_size(envelope) - 1)
       ) ==
         :error},
      {"each pair of the three shares rebuilds the seed (1+2, 1+3, 2+3)",
       rebuilt == [seed, seed, seed]},
      {"control: one share alone is refused",
       match?({:error, "two shares are needed" <> _}, read_shares([first_share]))},
      {"control: a share with one changed character is refused by its checksum",
       typo != first_share and
         match?({:error, "share 1: its checksum" <> _}, read_shares([typo, Enum.at(shares, 1)]))},
      {"recover rebuilds the seed from two shares and seals it to a software RSA key standing in for the TPM",
       match?({:ok, _}, recovered) and match?({:ok, _, ^seed, ^root}, open_checked(r, exe))},
      {"control: recover with a wrong ROOTHEX refuses and writes nothing",
       match?({:error, _}, recover_wrong) and not File.exists?(rw.dir)},
      {"enroll writes an envelope that install opens on another desk, with the same root",
       match?({:ok, _}, enrolled) and match?({:ok, _}, installed) and
         match?({:ok, _, ^seed, ^root}, open_checked(b, exe))},
      {"control: install with a wrong ROOTHEX refuses and writes nothing",
       match?({:error, _}, install_wrong) and after_c == before_c and match?({:ok, _}, install_c)},
      {"control: install refuses an envelope sealed to another desk and writes nothing",
       match?({:error, _}, install_other) and snapshot(d.dir) == before_d},
      {"a TPM that refuses OAEP-SHA256 is sealed with OAEP-SHA1, and status names it",
       String.starts_with?(to_e, "rsa-sha1:") and match?({:ok, _}, install_e) and
         Enum.any?(status_e, &String.ends_with?(&1, "RSA-OAEP-SHA1"))},
      {"adopt reads a keyring-encoded legacy entry (UTF-16LE Base64), checks its root and seals it",
       match?({:ok, _}, adopted) and
         length(Enum.filter(elem(adopted, 1), &String.starts_with?(&1, "FZ1-"))) == 3 and
         match?({:ok, _, ^seed, ^root}, open_checked(ad, exe))},
      {"control: adopt with a wrong ROOTHEX refuses and writes nothing",
       match?({:error, _}, adopt_wrong) and not File.exists?(aw.dir)},
      {"control: a legacy entry in another encoding (UTF-8 bytes) is refused",
       match?({:error, _}, adopt_utf8) and not File.exists?(utf8.dir)},
      {"a credential header passes when it holds what was asked: host+tpm2, or host",
       SealStore.check_creds_header(creds_header(host_tpm), "host+tpm2") == :ok and
         SealStore.check_creds_header(creds_header(host), "host") == :ok},
      {"control: a host-only credential header is refused when host+tpm2 was asked",
       match?({:error, _}, SealStore.check_creds_header(creds_header(host), "host+tpm2"))},
      {"control: an unscoped host header is refused where --user writes scoped ones",
       match?(
         {:error, _},
         SealStore.check_creds_header(creds_header("5a1c6a86df9d4096b1d5a65e0862f19a"), "host")
       )},
      {"a BCRYPT_RSAPUBLIC_BLOB converts to SubjectPublicKeyInfo DER and back to the same key",
       with(
         {:ok, {e, n}} <- SealStore.rsa_from_blob(blob),
         do: SealStore.from_spki(SealStore.spki(e, n))
       ) ==
         {:ok, {rsa_e, rsa_n}}},
      {"control: a blob with another magic is refused",
       match?({:error, _}, SealStore.rsa_from_blob(flip(blob, 0)))},
      {"control: --no-presence without an explicit --store is refused",
       match?({:error, "--no-presence" <> _}, store_ctx(%{no_presence: true}))}
    ]
  end

  def os_check(exe) do
    base = scratch("os_check")

    try do
      {rows, unchecked} =
        case host_os() do
          :macos -> os_check_macos(exe, base)
          :windows -> os_check_windows(exe, base)
          :linux -> os_check_linux(exe, base)
          other -> {[{"an OS store exists for #{other}", false}], []}
        end

      report(rows, unchecked)
    after
      File.rm_rf!(base)
    end
  end

  defp throwaway_seed do
    seed = :crypto.strong_rand_bytes(32)
    if Regex.match?(~r/\A[A-Za-z0-9]+=\z/, Base.encode64(seed)), do: seed, else: throwaway_seed()
  end

  defp os_check_macos(exe, base) do
    {:ok, probe_ctx} = store_ctx(%{store: Path.join(base, "probe"), no_presence: true})
    {probe, line} = SealStore.seal_cmd(probe_ctx, ["probe"])
    seed = throwaway_seed()
    {:ok, root} = public(exe, seed)
    keychain = Path.join(base, "legacy.keychain-db")
    password = SealStore.hex(:crypto.strong_rand_bytes(16))
    {_, 0} = System.cmd("/usr/bin/security", ["create-keychain", "-p", password, keychain])

    try do
      {_, 0} =
        System.cmd("/usr/bin/security", [
          "add-generic-password",
          "-s",
          "weftspun.fabric-zone",
          "-a",
          "offline-ca-root",
          "-w",
          Base.encode64(seed),
          keychain
        ])

      legacy = fn store ->
        ["--store", Path.join(base, store), "--no-presence", "--legacy-keychain", keychain]
      end

      {:ok, reader_ctx} =
        store_ctx(%{
          store: Path.join(base, "reader"),
          no_presence: true,
          legacy_keychain: keychain
        })

      read_row =
        {"the legacy read through /usr/bin/security returns the seed from a throwaway keychain",
         with({:ok, stored} <- reader_ctx.legacy.(), do: SealStore.decode_legacy(stored)) ==
           {:ok, seed}}

      if probe == 0 do
        adopted = run(["adopt", root] ++ legacy.("adopt"))
        adopt_wrong = run(["adopt", @pk_em] ++ legacy.("adopt-wrong"))
        {:ok, [to]} = run(["recipient", "--store", Path.join(base, "b"), "--no-presence"])
        envelope = Path.join(base, "b.envelope")

        enrolled =
          run(["enroll", to, envelope, "--store", Path.join(base, "adopt"), "--no-presence"])

        installed =
          run(["install", envelope, root, "--store", Path.join(base, "b"), "--no-presence"])

        {[
           {"fz_seal probe: #{line}", true},
           read_row,
           {"adopt seals the legacy seed to a Secure Enclave key, and public reproduces its root",
            match?({:ok, _}, adopted) and
              run(["public", "--store", Path.join(base, "adopt"), "--no-presence"]) ==
                {:ok, [root]}},
           {"control: adopt with a wrong ROOTHEX refuses and writes nothing",
            match?({:error, _}, adopt_wrong) and not File.exists?(Path.join(base, "adopt-wrong"))},
           {"enroll and install carry the seed to a second Enclave store with the same root",
            match?({:ok, _}, enrolled) and match?({:ok, _}, installed) and
              run(["public", "--store", Path.join(base, "b"), "--no-presence"]) == {:ok, [root]}}
         ], []}
      else
        {[
           {"fz_seal probe names the missing Secure Enclave: #{line}",
            probe == 3 and String.starts_with?(line, "secure-enclave unavailable")},
           read_row
         ],
         [
           "the Secure Enclave legs (adopt, public, enroll, install): this machine has no Secure Enclave"
         ]}
      end
    after
      System.cmd("/usr/bin/security", ["delete-keychain", keychain], stderr_to_stdout: true)
    end
  end

  defp os_check_windows(exe, base) do
    {:ok, ctx} = store_ctx(%{store: Path.join(base, "probe")})
    {probe, line} = SealStore.seal_cmd(ctx, ["probe"])
    value = :crypto.strong_rand_bytes(32)
    {protect, blob} = SealStore.seal_cmd(ctx, ["protect"], SealStore.hex(value))

    {plain, flipped} =
      case Base.decode16(blob, case: :mixed) do
        {:ok, bytes} when protect == 0 and byte_size(bytes) > 40 ->
          {elem(SealStore.seal_cmd(ctx, ["unprotect"], blob), 1),
           elem(
             SealStore.seal_cmd(
               ctx,
               ["unprotect"],
               SealStore.hex(flip(bytes, byte_size(bytes) - 10))
             ),
             0
           )}

        _ ->
          {nil, nil}
      end

    rows = [
      {"fz_seal probe names the TPM Platform Crypto Provider's state: #{line}",
       probe in [0, 3] and Regex.match?(~r/\Atpm-pcp (available|unavailable)/, line)},
      {"DPAPI protects and unprotects a throwaway value",
       protect == 0 and plain == SealStore.hex(value)},
      {"control: a flipped DPAPI blob is refused", flipped == 4}
    ]

    {tpm_rows, unchecked} =
      if probe == 0, do: {tpm_leg(ctx), []}, else: {[], ["the TPM leg: #{line}"]}

    {rows ++ tpm_rows ++ adopt_leg(exe, base, ctx), unchecked}
  end

  defp tpm_leg(ctx) do
    name = "fabric-zone offline-ca ci #{SealStore.hex(:crypto.strong_rand_bytes(4))}"
    {created, blob} = SealStore.seal_cmd(ctx, ["create", name])

    try do
      with 0 <- created,
           {:ok, bytes} <- Base.decode16(blob, case: :mixed),
           {:ok, public} <- SealStore.rsa_from_blob(bytes) do
        value = :crypto.strong_rand_bytes(32)
        opens = fn md -> SealStore.hex(SealStore.rsa_encrypt(public, value, md)) end

        md =
          Enum.find(
            ["sha256", "sha1"],
            &(SealStore.seal_cmd(ctx, ["unwrap", name, &1], opens.(&1)) ==
                {0, SealStore.hex(value)})
          )

        sealed = SealStore.rsa_encrypt(public, value, md || "sha256")

        {refused, _} =
          SealStore.seal_cmd(
            ctx,
            ["unwrap", name, md || "sha256"],
            SealStore.hex(flip(sealed, 100))
          )

        [
          {"a throwaway TPM key opens RSA-OAEP-#{md} ciphertext from OTP", md != nil},
          {"control: a flipped RSA ciphertext is refused by the TPM", refused == 4}
        ]
      else
        _ ->
          [{"a throwaway TPM key is created (fz_seal create exited #{inspect(created)})", false}]
      end
    after
      {deleted, _} = SealStore.seal_cmd(ctx, ["delete-key", name])
      IO.puts("throwaway TPM key #{name}: delete-key exited #{deleted}")
    end
  end

  # --dpapi only takes effect where no TPM is usable; the row names the mechanism that holds the seed.
  defp adopt_leg(exe, base, ctx) do
    seed = throwaway_seed()
    {:ok, root} = public(exe, seed)
    target = "fabric-zone-ci-adopt-#{SealStore.hex(:crypto.strong_rand_bytes(4))}"
    dpapi = ["--dpapi"]
    store = Path.join(base, "adopt")
    wrong = Path.join(base, "adopt-wrong")

    {_, stored} =
      System.cmd("cmdkey", [
        "/generic:#{target}",
        "/user:offline-ca-root",
        "/pass:#{Base.encode64(seed)}"
      ])

    try do
      {_, raw} = SealStore.seal_cmd(ctx, ["legacy-read", target])
      adopted = run(["adopt", root, "--store", store, "--legacy-target", target] ++ dpapi)
      adopt_wrong = run(["adopt", @pk_em, "--store", wrong, "--legacy-target", target] ++ dpapi)

      mechanism =
        with {:ok, key} <- SealStore.load_key(%{ctx | dir: store}),
             do: key["mechanism"],
             else: (_ -> "no key")

      [
        {"cmdkey writes a throwaway generic credential", stored == 0},
        {"cmdkey stores the password as UTF-16LE with no terminator, as keyring 3.6.3 does",
         raw ==
           SealStore.hex(
             :unicode.characters_to_binary(Base.encode64(seed), :utf8, {:utf16, :little})
           )},
        {"adopt seals the seed from a throwaway generic credential (#{mechanism}), and public reproduces its root",
         match?({:ok, _}, adopted) and run(["public", "--store", store]) == {:ok, [root]}},
        {"control: adopt with a wrong ROOTHEX refuses and writes nothing",
         match?({:error, _}, adopt_wrong) and not File.exists?(wrong)}
      ]
    after
      System.cmd("cmdkey", ["/delete:#{target}"], stderr_to_stdout: true)

      with {:ok, %{"mechanism" => "tpm-pcp", "key-name" => name}} <-
             SealStore.load_key(%{ctx | dir: store}) do
        SealStore.seal_cmd(ctx, ["delete-key", name])
      end
    end
  end

  defp os_check_linux(_exe, base) do
    store = Path.join(base, "store")

    case SealStore.systemd_version() do
      {:ok, version} ->
        init = run(["init", "--store", store])

        {[
           {"systemd #{version}: init seals a seed with systemd-creds, and public reproduces its root",
            match?({:ok, _}, init) and match?({:ok, [_]}, run(["public", "--store", store]))}
         ], []}

      {:error, message} ->
        refused = run(["init", "--store", store])

        {[
           {"the Linux store refuses with the named error and writes nothing: #{message}",
            String.starts_with?(message, "systemd-below-256") and
              match?({:error, "systemd-below-256" <> _}, refused) and
              not File.exists?(store)}
         ], ["the systemd-creds round trip: #{message}"]}
    end
  end

  defp report(rows, unchecked \\ []) do
    Enum.each(rows, fn {label, ok} -> IO.puts("#{if ok, do: "ok  ", else: "FAIL"} #{label}") end)
    Enum.each(unchecked, &IO.puts("UNCHECKED #{&1}"))
    failed = Enum.count(rows, fn {_, ok} -> not ok end)
    tail = if unchecked == [], do: "", else: ", #{length(unchecked)} unchecked"

    IO.puts(
      "RESULT: #{if failed == 0, do: "PASS", else: "FAIL"} (#{length(rows)} checks, #{failed} failed#{tail})"
    )

    if failed == 0, do: :ok, else: {:error, "#{failed} of #{length(rows)} checks failed"}
  end
end

OfflineCa.main(System.argv())
