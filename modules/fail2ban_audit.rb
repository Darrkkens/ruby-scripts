# frozen_string_literal: true

module Modules
  class Fail2BanAudit
    def initialize(output)
      @output = output
    end

    def run
      @output.section('Status do Fail2Ban')

      unless installed?
        @output.status('Fail2Ban', :error, 'nao instalado')
        @output.item('Instale com: sudo apt install fail2ban')
        return
      end

      @output.status('Fail2Ban', :ok, 'instalado')
      check_service_state
      check_jails
    end

    private

    def installed?
      Utils::Shell.which('fail2ban-client') || Utils::Shell.run('dpkg -s fail2ban', timeout: 10).success?
    end

    def check_service_state
      active = Utils::Shell.run('systemctl is-active fail2ban', timeout: 15).stdout.strip
      enabled = Utils::Shell.run('systemctl is-enabled fail2ban', timeout: 15).stdout.strip

      @output.status('Servico ativo', active == 'active' ? :ok : :warn, active.empty? ? 'nao foi possivel consultar o systemd' : active)
      @output.status('Inicio automatico', enabled == 'enabled' ? :ok : :warn, enabled.empty? ? 'nao foi possivel consultar o systemd' : enabled)
    end

    def check_jails
      result = Utils::Shell.run('fail2ban-client status', timeout: 30)

      unless result.success?
        @output.status('Consulta de jails', :warn, blank_or(result.output, 'falha ao executar fail2ban-client'))
        return
      end

      jails = parse_jails(result.stdout)
      if jails.empty?
        @output.status('Jails ativas', :warn, 'nenhuma jail listada')
        return
      end

      @output.status('Jails ativas', :ok, jails.join(', '))
      jails.each do |jail|
        jail_result = Utils::Shell.run("fail2ban-client status #{Utils::Shell.build(jail)}", timeout: 20)
        if jail_result.success?
          summarize_jail(jail, jail_result.stdout)
        else
          @output.status("Jail #{jail}", :warn, blank_or(jail_result.output, 'nao foi possivel obter detalhes'))
        end
      end
    end

    def summarize_jail(jail, text)
      currently_failed = text[/Currently failed:\s+(\d+)/i, 1]
      currently_banned = text[/Currently banned:\s+(\d+)/i, 1]
      total_banned = text[/Total banned:\s+(\d+)/i, 1]

      @output.key_value("Jail #{jail}", "falhas atuais=#{currently_failed || '?'} | bans atuais=#{currently_banned || '?'} | total bans=#{total_banned || '?'}")
    end

    def parse_jails(text)
      line = text.lines.find { |entry| entry.include?('Jail list:') }
      return [] unless line

      line.split(':', 2).last.to_s.split(',').map(&:strip).reject(&:empty?)
    end

    def blank_or(value, fallback)
      text = value.to_s.strip
      text.empty? ? fallback : text
    end
  end
end
