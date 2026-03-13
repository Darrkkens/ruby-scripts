# frozen_string_literal: true

module Modules
  class SubdomainScanner
    COMMON_SUBDOMAINS = %w[
      www
      api
      app
      admin
      blog
      cdn
      ci
      dashboard
      dev
      docs
      ftp
      git
      imap
      mail
      monitor
      ns1
      ns2
      panel
      portal
      smtp
      status
      stage
      vpn
      webmail
      shop
    ].freeze

    NMAP_PORTS = '22,80,443,8080,8443'

    def initialize(output)
      @output = output
    end

    def run
      @output.section('Scanner basico de subdominios')

      domain = @output.prompt('Dominio alvo (ex: exemplo.com):').strip.downcase
      unless Utils::Validators.domain?(domain)
        @output.status('Dominio invalido', :error, 'informe um FQDN valido, por exemplo `empresa.com`')
        return
      end

      validate_dns = Utils::Validators.yes?(@output.prompt('Validar resolucao DNS agora? [S/n]:'), default: true)
      scan_ports = Utils::Validators.yes?(@output.prompt("Executar Nmap em #{NMAP_PORTS}? [s/N]:"), default: false)

      if scan_ports && !validate_dns
        validate_dns = true
        @output.status('Resolucao DNS', :info, 'habilitada automaticamente porque o Nmap depende de nomes validos')
      end

      candidates = COMMON_SUBDOMAINS.map { |prefix| "#{prefix}.#{domain}" }
      @output.status('Wordlist', :info, "#{candidates.size} candidatos comuns")

      discovered = candidates.filter_map do |hostname|
        addresses = validate_dns ? Utils::Validators.resolve(hostname) : []
        next if validate_dns && addresses.empty?

        { hostname: hostname, addresses: addresses }
      end

      if discovered.empty?
        @output.status(validate_dns ? 'Subdominios encontrados' : 'Candidatos gerados',
                       validate_dns ? :warn : :info,
                       validate_dns ? 'nenhum subdominio da wordlist resolveu DNS' : 'nenhum resultado validado porque a resolucao foi desabilitada')
        candidates.first(10).each { |hostname| @output.item(hostname) } unless validate_dns
        return
      end

      summary_label = validate_dns ? 'Subdominios encontrados' : 'Candidatos gerados'
      summary_level = validate_dns ? :ok : :info
      @output.status(summary_label, summary_level, "#{discovered.size} entrada(s)")
      discovered.each do |entry|
        addresses = entry[:addresses].empty? ? 'resolucao nao validada' : entry[:addresses].join(', ')
        @output.key_value(entry[:hostname], addresses)
      end

      return unless scan_ports

      unless Utils::NmapHelper.available?
        @output.status('Nmap', :warn, 'nao instalado; instale `nmap` para varrer portas comuns')
        return
      end

      @output.section('Nmap em subdominios descobertos')
      discovered.first(10).each do |entry|
        result = Utils::NmapHelper.scan(entry[:hostname], ports: NMAP_PORTS, service_detection: false, timeout: 60)
        if result[:ok]
          summarize_ports(entry[:hostname], result[:hosts])
        else
          @output.status(entry[:hostname], :warn, result[:error])
        end
      end
    end

    private

    def summarize_ports(hostname, hosts)
      ports = hosts.flat_map { |host| host[:ports] }
      if ports.empty?
        @output.status(hostname, :ok, 'nenhuma porta aberta encontrada nas portas comuns consultadas')
      else
        summary = ports.map { |port| "#{port[:port]}/#{port[:protocol]}" }.join(', ')
        @output.status(hostname, :warn, "portas abertas: #{summary}")
      end
    end
  end
end
