# SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
# SPDX-License-Identifier: MIT
# The offline root's seed in the OS secret store, fed to fz_offline_ca, and FoundationDB TLS on localhost
# that trusts only that root: elixir tools/offline_ca.exs init | public | issue LABEL DIR | fdb-e2e DIR | --self-test
Mix.install([
  {:keychain,
   github: "V-Sekai-fire/contract-keychain", ref: "5f1e50440b9518197254d7333fe318123aa7ead9"}
])

defmodule OfflineCa do
  @package "weftspun"
  @service "fabric-zone"
  @user "offline-ca-root"
  @suffix ".fdb.fabric.internal"
  @leaf_seconds 3600
  @root_seconds 365 * 86_400
  @fdb_port 4690
  @repo Path.expand("..", __DIR__)
  @build Path.join(@repo, "build/offline_ca")
  @ikm_e "4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e"
  @pk_em "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"

  def main(args) do
    case run(args) do
      :ok ->
        :ok

      {:error, message} ->
        IO.puts(:stderr, "FAIL #{message}")
        System.halt(1)
    end
  end

  defp run(["init"]) do
    with :ok <- init(), {:ok, seed} <- seed(), {:ok, hex} <- public(cli(), seed) do
      IO.puts("stored #{entry()}; root public key #{hex}")
    end
  end

  defp run(["public"]) do
    with {:ok, seed} <- seed(), {:ok, hex} <- public(cli(), seed), do: IO.puts(hex)
  end

  defp run(["issue", label, dir]) do
    now = System.os_time(:second) - 60
    prefix = Path.join(dir, label)

    with {:ok, seed} <- seed(),
         exe = cli(),
         :ok <- root(exe, seed, dir, now),
         :ok <- issue(exe, seed, label <> @suffix, prefix, now, @leaf_seconds) do
      IO.puts(
        "wrote #{Path.join(dir, "root.pem")}, #{prefix}.key and #{prefix}.pem for #{label <> @suffix}"
      )
    end
  end

  defp run(["fdb-e2e", dir | control]) when control in [[], ["--control=trust-other-root"]] do
    with {:ok, seed} <- seed(), do: fdb_e2e(cli(), seed, Path.expand(dir), control != [])
  end

  defp run(["--self-test"]), do: self_test(cli())

  defp run(_),
    do:
      {:error,
       "usage: init | public | issue LABEL DIR | fdb-e2e DIR [--control=trust-other-root] | --self-test"}

  def entry, do: "#{Keychain.service_name(@package, @service)} / #{@user}"

  def seed do
    case Keychain.get_password(@package, @service, @user) do
      {:ok, seed} ->
        {:ok, seed}

      {:error, :not_found} ->
        {:error, "no seed in the OS store under #{entry()}; only `init` makes one"}

      {:error, message} ->
        {:error, "the OS store: #{message}"}
    end
  end

  def init do
    case Keychain.get_password(@package, @service, @user) do
      {:ok, _} -> {:error, "#{entry()} already holds a seed; init never replaces one"}
      {:error, :not_found} -> store(Base.encode64(:crypto.strong_rand_bytes(32)))
      {:error, message} -> {:error, "the OS store: #{message}"}
    end
  end

  defp store(seed) do
    with :ok <- Keychain.set_password(@package, @service, @user, seed),
         {:ok, ^seed} <- Keychain.get_password(@package, @service, @user) do
      :ok
    else
      _ -> {:error, "the OS store did not keep the seed under #{entry()}"}
    end
  end

  def cli do
    windows = windows?()
    exe = Path.join(@build, if(windows, do: "fz_offline_ca.exe", else: "fz_offline_ca"))

    unless File.exists?(Path.join(@build, "CMakeCache.txt")) do
      generator = if windows, do: ["-G", "MinGW Makefiles"], else: []

      sh!(
        "cmake",
        ["-S", @repo, "-B", @build, "-DFZ_NATIVE=ON", "-DCMAKE_BUILD_TYPE=Release"] ++ generator
      )
    end

    sh!("cmake", ["--build", @build, "--target", "fz_offline_ca", "-j", "8"])
    exe
  end

  defp sh!(cmd, args) do
    case System.cmd(cmd, args, stderr_to_stdout: true) do
      {_, 0} -> :ok
      {out, status} -> raise "#{cmd} exited #{status}:\n#{out}"
    end
  end

  defp windows?, do: match?({:win32, _}, :os.type())

  def ca(exe, seed, args) do
    port =
      Port.open({:spawn_executable, exe}, [:binary, :exit_status, :stderr_to_stdout, args: args])

    Port.command(port, seed <> "\n")
    collect(port, "")
  end

  defp collect(port, out) do
    receive do
      {^port, {:data, data}} -> collect(port, out <> data)
      {^port, {:exit_status, status}} -> {status, out}
    after
      30_000 -> {:timeout, out}
    end
  end

  def public(exe, seed) do
    case ca(exe, seed, ["public"]) do
      {0, hex} -> {:ok, String.trim(hex)}
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
    do: {:error, "fz_offline_ca exited #{status}: #{String.trim(out)}"}

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
      other = Base.encode64(:crypto.strong_rand_bytes(32))
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

  def self_test(exe) do
    Application.put_env(:keychain, :backend, Keychain.Mock)
    Keychain.Mock.start()
    Keychain.Mock.reset()

    dir =
      Path.join(System.tmp_dir!(), "offline_ca_self_test_#{System.unique_integer([:positive])}")

    File.mkdir_p!(dir)
    kat = Base.encode64(Base.decode16!(@ikm_e, case: :lower))
    <<first, rest::binary>> = Base.decode16!(@ikm_e, case: :lower)
    flipped = Base.encode64(<<Bitwise.bxor(first, 1), rest::binary>>)
    short = Base.encode64(binary_part(Base.decode16!(@ikm_e, case: :lower), 0, 31))
    no_seed = run(["issue", "local-client", dir])
    nothing_written = File.ls!(dir) == []
    first_init = init()
    {:ok, stored} = Keychain.get_password(@package, @service, @user)
    second_init = init()

    rows = [
      {"RFC 9180 A.3 through fz_offline_ca: ikmE gives pkEm", public(exe, kat) == {:ok, @pk_em}},
      {"control: one flipped seed bit gives another root",
       match?({:ok, hex} when hex != @pk_em, public(exe, flipped))},
      {"control: a 31-byte seed is refused", match?({2, _}, ca(exe, short, ["public"]))},
      {"control: with no stored seed, issue refuses and writes nothing",
       match?({:error, _}, no_seed) and nothing_written},
      {"init stores a seed that derives a root",
       first_init == :ok and match?({:ok, _}, public(exe, stored))},
      {"control: a second init refuses and keeps the first seed",
       match?({:error, _}, second_init) and
         Keychain.get_password(@package, @service, @user) == {:ok, stored}},
      {"the stored seed gives the same root on every run",
       public(exe, stored) == public(exe, stored)}
    ]

    File.rm_rf!(dir)
    report(rows)
  end

  defp report(rows) do
    Enum.each(rows, fn {label, ok} -> IO.puts("#{if ok, do: "ok  ", else: "FAIL"} #{label}") end)
    failed = Enum.count(rows, fn {_, ok} -> not ok end)

    IO.puts(
      "RESULT: #{if failed == 0, do: "PASS", else: "FAIL"} (#{length(rows)} checks, #{failed} failed)"
    )

    if failed == 0, do: :ok, else: {:error, "#{failed} of #{length(rows)} checks failed"}
  end
end

OfflineCa.main(System.argv())
