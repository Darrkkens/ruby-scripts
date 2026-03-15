# frozen_string_literal: true

require_relative '../utils/service_monitor'

module Modules
  class ServiceMonitorAudit
    def initialize(output)
      @output = output
    end

    def run
      @output.section('Monitoramento de servico systemd')

      service = read_service_name
      mode = @output.prompt('Modo [1=checagem unica, 2=monitor continuo]:').strip
      lines = read_positive_integer('Linhas de log em falha/reinicio [20]:', Utils::ServiceMonitor::DEFAULT_LINES)

      case mode
      when '1'
        run_once(service, lines)
      when '2'
        interval = read_positive_integer('Intervalo entre checagens em segundos [5]:', Utils::ServiceMonitor::DEFAULT_INTERVAL)
        run_continuous(service, interval, lines)
      else
        @output.status('Modo invalido', :warn, 'use 1 ou 2')
      end
    end

    private

    def read_service_name
      value = @output.prompt("Servico systemd [#{Utils::ServiceMonitor::DEFAULT_SERVICE}]:").strip
      value.empty? ? Utils::ServiceMonitor::DEFAULT_SERVICE : value
    end

    def read_positive_integer(prompt, default)
      value = @output.prompt(prompt).strip
      return default if value.empty?

      integer = Integer(value, 10)
      raise ArgumentError if integer <= 0

      integer
    rescue ArgumentError
      @output.status('Valor invalido', :warn, "usando padrao #{default}")
      default
    end

    def run_once(service, lines)
      monitor = build_monitor(service, Utils::ServiceMonitor::DEFAULT_INTERVAL, lines)
      healthy = monitor.run(once: true)
      @output.status('Resultado final', healthy ? :ok : :warn, healthy ? 'servico ativo e em execucao' : 'servico fora do estado esperado')
    rescue Utils::ServiceMonitorError => e
      @output.status('Monitoramento', :error, e.message)
    end

    def run_continuous(service, interval, lines)
      monitor = build_monitor(service, interval, lines)
      previous_handlers = install_stop_handlers(monitor)

      @output.status('Monitoramento', :info, 'pressione CTRL+C para parar e voltar ao menu')
      healthy = monitor.run
      @output.status('Monitoramento encerrado', healthy ? :info : :warn, healthy ? 'ultimo estado saudavel' : 'ultimo estado fora do esperado')
    rescue Utils::ServiceMonitorError => e
      @output.status('Monitoramento', :error, e.message)
    ensure
      restore_handlers(previous_handlers)
    end

    def build_monitor(service, interval, lines)
      Utils::ServiceMonitor.new(
        service: service,
        interval: interval,
        lines: lines,
        emitter: @output.method(:line)
      )
    end

    def install_stop_handlers(monitor)
      %w[INT TERM].each_with_object({}) do |signal, handlers|
        handlers[signal] = Signal.trap(signal) { monitor.request_stop }
      end
    end

    def restore_handlers(handlers)
      return unless handlers

      handlers.each do |signal, handler|
        Signal.trap(signal, handler)
      end
    end
  end
end
