# frozen_string_literal: true

module Modules
  class CVEScanner
    def initialize(output)
      @output = output
    end

    def run
      @output.section('Scanner basico de CVEs')
      @output.line('Metodo: Nmap para detectar banners/versoes e base heuristica local para alertas defensivos.')

      target = @output.prompt('Alvo autorizado (hostname ou IPv4):').strip
      unless Utils::Validators.host_or_ipv4?(target)
        @output.status('Alvo invalido', :error, 'informe um hostname ou IPv4 simples')
        return
      end

      unless Utils::NmapHelper.available?
        @output.status('Nmap', :error, 'nao instalado; instale `nmap` para usar este modulo')
        return
      end

      result = Utils::NmapHelper.scan(target, service_detection: true, top_ports: 100, timeout: 180)
      unless result[:ok]
        @output.status('Nmap', :warn, result[:error])
        return
      end

      hosts = result[:hosts]
      if hosts.empty?
        @output.status('Resultados', :warn, 'nenhum host retornado pelo nmap')
        return
      end

      @output.status('Aviso metodologico', :info, 'banners podem refletir backports do Debian; trate os achados como triagem inicial')
      hosts.each do |host|
        summarize_host(host)
      end
    end

    private

    def summarize_host(host)
      label = ([host[:address]] + host[:hostnames]).compact.reject(&:empty?).uniq.join(' / ')
      @output.divider
      @output.key_value('Host', label.empty? ? 'desconhecido' : label)

      if host[:ports].empty?
        @output.status('Servicos abertos', :ok, 'nenhuma porta aberta detectada no escopo consultado')
        return
      end

      host[:ports].each do |service|
        service_label = format_service(service)
        @output.key_value('Servico', service_label)
        matches = Utils::CVEBaseline.match(service)

        if matches.empty?
          @output.status('Triagem de CVE', :ok, 'nenhum candidato simples na base local')
        else
          matches.each do |match|
            @output.status("Triagem de CVE - #{match[:title]}", match[:severity], match[:advice])
          end
        end
      end
    end

    def format_service(service)
      pieces = ["#{service[:port]}/#{service[:protocol]}", service[:name], service[:product], service[:version], service[:extrainfo]]
      pieces.compact.map(&:strip).reject(&:empty?).join(' | ')
    end
  end
end
