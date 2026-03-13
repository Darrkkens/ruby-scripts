# frozen_string_literal: true

module Modules
  class MinerAudit
    HIGH_CPU_THRESHOLD = 40.0
    SUSPICIOUS_PATTERN = /\b(xmrig|minerd|cpuminer|nanominer|kinsing|kdevtmpfsi|watchdogx|stratum|hashvault|cryptonight)\b/i
    SUSPICIOUS_PORTS = %w[3333 4444 5555 6666 7777 8332 8333 8888 9999 14444 20580].freeze

    def initialize(output)
      @output = output
    end

    def run
      @output.section('Deteccao basica de crypto miners')
      @output.line('Escopo: analise heuristica de processos, conexoes e sinais simples de persistencia.')

      processes = load_processes
      check_high_cpu(processes)
      check_suspicious_names(processes)
      check_network_connections
      check_persistence_indicators
    end

    private

    def load_processes
      result = Utils::Shell.run('ps -eo pid,user,%cpu,%mem,comm,args --no-headers --sort=-%cpu', timeout: 20)
      result.stdout.lines.filter_map do |line|
        pid, user, cpu, mem, comm, args = line.strip.split(/\s+/, 6)
        next unless pid && cpu && comm

        {
          pid: pid,
          user: user,
          cpu: cpu.to_f,
          mem: mem.to_f,
          comm: comm,
          args: args.to_s
        }
      end
    end

    def check_high_cpu(processes)
      findings = processes.reject { |process| noisy_process?(process) }
                          .select { |process| process[:cpu] >= HIGH_CPU_THRESHOLD }
                          .first(8)

      if findings.empty?
        @output.status('Processos com CPU alta', :ok, "nenhum processo acima de #{HIGH_CPU_THRESHOLD}%")
      else
        @output.status('Processos com CPU alta', :warn, "#{findings.size} processo(s) acima de #{HIGH_CPU_THRESHOLD}%")
        findings.each do |process|
          @output.item(format_process(process))
        end
      end
    end

    def check_suspicious_names(processes)
      findings = processes.select do |process|
        [process[:comm], process[:args]].join(' ') =~ SUSPICIOUS_PATTERN
      end.first(10)

      if findings.empty?
        @output.status('Nomes de processos suspeitos', :ok, 'nenhum nome conhecido de miner encontrado')
      else
        @output.status('Nomes de processos suspeitos', :warn, "#{findings.size} processo(s) destacado(s)")
        findings.each { |process| @output.item(format_process(process)) }
      end
    end

    def check_network_connections
      command = if Utils::Shell.which('ss')
                  'ss -tunpH'
                elsif Utils::Shell.which('netstat')
                  'netstat -plant 2>/dev/null | sed -n "3,20p"'
                end

      unless command
        @output.status('Conexoes suspeitas', :info, 'nem `ss` nem `netstat` estao disponiveis')
        return
      end

      result = Utils::Shell.run(command, timeout: 20)
      findings = result.stdout.lines.map(&:strip).select do |line|
        SUSPICIOUS_PORTS.any? { |port| line.match?(/:#{port}\b/) }
      end.first(10)

      if findings.empty?
        @output.status('Conexoes suspeitas', :ok, 'nenhuma conexao destacada em portas comuns de pools')
      else
        @output.status('Conexoes suspeitas', :warn, "#{findings.size} conexao(oes) destacada(s)")
        findings.each { |line| @output.item(line) }
      end
    end

    def check_persistence_indicators
      command = [
        "grep -RniE 'xmrig|minerd|cpuminer|nanominer|stratum|xmrig-proxy|kdevtmpfsi|kinsing|watchdogx'",
        '/etc/cron*',
        '/var/spool/cron/crontabs',
        '/etc/systemd/system',
        '2>/dev/null | sed -n "1,10p"'
      ].join(' ')

      result = Utils::Shell.run(command, timeout: 30)
      findings = result.stdout.lines.map(&:strip).reject(&:empty?)

      if findings.empty?
        @output.status('Persistencia suspeita', :ok, 'nenhum indicador simples encontrado em cron/systemd')
      else
        @output.status('Persistencia suspeita', :warn, "#{findings.size} referencia(s) destacada(s)")
        findings.each { |line| @output.item(line) }
      end
    end

    def format_process(process)
      "PID=#{process[:pid]} USER=#{process[:user]} CPU=#{process[:cpu]} MEM=#{process[:mem]} COMM=#{process[:comm]} CMD=#{process[:args][0, 120]}"
    end

    def noisy_process?(process)
      process[:pid].to_i == Process.pid || %w[ps top htop].include?(process[:comm])
    end
  end
end
