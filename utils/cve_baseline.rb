# frozen_string_literal: true

require 'rubygems/version'

module Utils
  module CVEBaseline
    RULES = [
      {
        title: 'OpenSSH aparentemente antigo',
        severity: :warn,
        detector: lambda { |service|
          Utils::CVEBaseline.product_match?(service, 'openssh') &&
            Utils::CVEBaseline.version_lt?(Utils::CVEBaseline.version_for(service), '8.9')
        },
        advice: 'Revise boletins da familia OpenSSH e confirme backports do Debian antes de tratar a versao detectada como vulneravel.'
      },
      {
        title: 'Apache httpd em versoes 2.4.49/2.4.50',
        severity: :error,
        detector: lambda { |service|
          Utils::CVEBaseline.product_match?(service, 'apache') &&
            %w[2.4.49 2.4.50].include?(Utils::CVEBaseline.normalized_version(Utils::CVEBaseline.version_for(service)))
        },
        advice: 'Essas versoes ficaram associadas a falhas graves de path traversal e execucao remota. Atualize imediatamente se o banner estiver correto.'
      },
      {
        title: 'Nginx em ramo antigo',
        severity: :warn,
        detector: lambda { |service|
          Utils::CVEBaseline.product_match?(service, 'nginx') &&
            Utils::CVEBaseline.version_lt?(Utils::CVEBaseline.version_for(service), '1.20')
        },
        advice: 'Ramos antigos de nginx acumulam diversas correcoes. Valide a origem do pacote e os backports aplicados.'
      },
      {
        title: 'OpenSSL legado',
        severity: :warn,
        detector: lambda { |service|
          Utils::CVEBaseline.product_match?(service, 'openssl') &&
            Utils::CVEBaseline.version_lt?(Utils::CVEBaseline.version_for(service), '3.0')
        },
        advice: 'Bibliotecas OpenSSL anteriores a 3.x concentram historico relevante de CVEs. Confirme a versao real do pacote no sistema.'
      },
      {
        title: 'Redis em ramo antigo',
        severity: :warn,
        detector: lambda { |service|
          Utils::CVEBaseline.service_name?(service, 'redis') &&
            Utils::CVEBaseline.version_lt?(Utils::CVEBaseline.version_for(service), '6.2')
        },
        advice: 'Instancias Redis antigas e expostas em rede merecem revisao de autenticacao, bind e atualizacao.'
      },
      {
        title: 'MySQL/MariaDB em ramo antigo',
        severity: :warn,
        detector: lambda { |service|
          Utils::CVEBaseline.legacy_database?(service)
        },
        advice: 'Verifique CVEs do ramo detectado e restrinja a exposicao do banco a redes confiaveis.'
      },
      {
        title: 'PostgreSQL em ramo antigo',
        severity: :warn,
        detector: lambda { |service|
          Utils::CVEBaseline.service_name?(service, 'postgresql') &&
            Utils::CVEBaseline.version_lt?(Utils::CVEBaseline.version_for(service), '13')
        },
        advice: 'Revise updates acumulados do PostgreSQL e a politica de exposicao do servico.'
      },
      {
        title: 'Exim em ramo antigo',
        severity: :warn,
        detector: lambda { |service|
          Utils::CVEBaseline.product_match?(service, 'exim') &&
            Utils::CVEBaseline.version_lt?(Utils::CVEBaseline.version_for(service), '4.96')
        },
        advice: 'Exim antigo recebeu varias correcoes criticas. Confirme o pacote instalado e aplique atualizacoes.'
      }
    ].freeze

    module_function

    def match(service)
      RULES.filter_map do |rule|
        next unless rule[:detector].call(service)

        {
          title: rule[:title],
          severity: rule[:severity],
          advice: rule[:advice]
        }
      end
    end

    def product_match?(service, term)
      haystack = [service[:product], service[:name]].compact.join(' ').downcase
      haystack.include?(term.downcase)
    end

    def service_name?(service, term)
      service[:name].to_s.downcase.include?(term.downcase)
    end

    def legacy_database?(service)
      if product_match?(service, 'mariadb')
        version_lt?(version_for(service), '10.5')
      elsif product_match?(service, 'mysql') || service_name?(service, 'mysql')
        version_lt?(version_for(service), '8.0')
      else
        false
      end
    end

    def version_for(service)
      service[:version].to_s
    end

    def normalized_version(raw_version)
      raw_version.to_s.scan(/\d+/).join('.')
    end

    def version_lt?(raw_version, baseline)
      normalized = normalized_version(raw_version)
      return false if normalized.empty?

      Gem::Version.new(normalized) < Gem::Version.new(baseline)
    rescue ArgumentError
      false
    end
  end
end
