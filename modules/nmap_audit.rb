# frozen_string_literal: true

module Modules
  class NmapAudit
    def initialize(output)
      @output = output
    end

    def run
      @output.section('Integracao com Nmap')
      @output.line('Use este modulo apenas para auditoria local ou de alvos autorizados.')

      unless Utils::NmapHelper.available?
        @output.status('Nmap', :error, 'nao instalado; instale `nmap` para usar este modulo')
        return
      end

      target = @output.prompt('Alvo autorizado (hostname ou IPv4):').strip
      unless Utils::Validators.host_or_ipv4?(target)
        @output.status('Alvo invalido', :error, 'informe um hostname ou IPv4 simples')
        return
      end

      mode = @output.prompt('Modo [1=portas comuns, 2=versoes de servicos, 3=portas especificas]:').strip
      result = case mode
               when '1'
                 Utils::NmapHelper.scan(target, top_ports: 100, timeout: 120)
               when '2'
                 Utils::NmapHelper.scan(target, service_detection: true, top_ports: 100, timeout: 180)
               when '3'
                 run_specific_ports(target)
               else
                 @output.status('Modo invalido', :warn, 'use 1, 2 ou 3')
                 return
               end

      return unless result
      return @output.status('Nmap', :warn, result[:error]) unless result[:ok]

      summarize_results(result[:hosts], service_detection: mode != '1')
    end

    private

    def run_specific_ports(target)
      ports = @output.prompt('Informe portas separadas por virgula (ex: 22,80,443):').strip
      unless Utils::Validators.port_list?(ports)
        @output.status('Lista de portas invalida', :error, 'use apenas numeros e virgulas')
        return nil
      end

      Utils::NmapHelper.scan(target, ports: ports, service_detection: true, timeout: 180)
    end

    def summarize_results(hosts, service_detection:)
      if hosts.empty?
        @output.status('Resultado', :warn, 'nenhum host retornado pelo nmap')
        return
      end

      hosts.each do |host|
        label = ([host[:address]] + host[:hostnames]).compact.reject(&:empty?).uniq.join(' / ')
        @output.divider
        @output.key_value('Host', label.empty? ? 'desconhecido' : label)

        if host[:ports].empty?
          @output.status('Portas abertas', :ok, 'nenhuma porta aberta detectada')
          next
        end

        host[:ports].each do |port|
          message = "#{port[:port]}/#{port[:protocol]}"
          if service_detection
            details = [port[:name], port[:product], port[:version], port[:extrainfo]].compact.reject(&:empty?).join(' | ')
            @output.key_value(message, details.empty? ? 'servico sem banner detalhado' : details)
          else
            @output.key_value('Porta aberta', message)
          end
        end
      end
    end
  end
end
