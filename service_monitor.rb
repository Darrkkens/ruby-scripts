#!/usr/bin/env ruby
# frozen_string_literal: true

require 'optparse'
require_relative 'utils/service_monitor'

options = {
  service: Utils::ServiceMonitor::DEFAULT_SERVICE,
  interval: Utils::ServiceMonitor::DEFAULT_INTERVAL,
  lines: Utils::ServiceMonitor::DEFAULT_LINES,
  once: false
}

parser = OptionParser.new do |option_parser|
  option_parser.banner = 'Uso: ruby service_monitor.rb [opcoes]'

  option_parser.on('-s', '--service NAME', 'Nome do servico systemd') do |value|
    options[:service] = value
  end

  option_parser.on('-i', '--interval SEGUNDOS', Integer, 'Intervalo entre checagens (padrao: 5)') do |value|
    raise OptionParser::InvalidArgument, 'o intervalo deve ser maior que zero' if value <= 0

    options[:interval] = value
  end

  option_parser.on('-n', '--lines NUM', Integer, 'Quantidade de linhas de log exibidas em falhas (padrao: 20)') do |value|
    raise OptionParser::InvalidArgument, 'a quantidade de linhas deve ser maior que zero' if value <= 0

    options[:lines] = value
  end

  option_parser.on('--once', 'Executa apenas uma checagem e sai com codigo 0/1') do
    options[:once] = true
  end

  option_parser.on('-h', '--help', 'Mostra esta ajuda') do
    puts option_parser
    exit 0
  end
end

begin
  parser.parse!
rescue OptionParser::ParseError => e
  warn "Erro: #{e.message}"
  warn "Use --help para ver as opcoes."
  exit 1
end

begin
  monitor = Utils::ServiceMonitor.new(
    service: options[:service],
    interval: options[:interval],
    lines: options[:lines]
  )

  previous_handlers = %w[INT TERM].each_with_object({}) do |signal, handlers|
    handlers[signal] = Signal.trap(signal) { monitor.request_stop }
  end

  healthy = monitor.run(once: options[:once])
  puts 'Monitoramento encerrado.' unless options[:once]
  exit(healthy ? 0 : 1) if options[:once]
rescue Utils::ServiceMonitorError => e
  warn e.message
  exit 1
ensure
  if defined?(previous_handlers) && previous_handlers
    previous_handlers.each do |signal, handler|
      Signal.trap(signal, handler)
    end
  end
end
