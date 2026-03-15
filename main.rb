# frozen_string_literal: true

require_relative 'utils/output'
require_relative 'utils/shell'
require_relative 'utils/validators'
require_relative 'utils/nmap_helper'
require_relative 'utils/cve_baseline'
require_relative 'modules/rootkit_audit'
require_relative 'modules/fail2ban_audit'
require_relative 'modules/miner_audit'
require_relative 'modules/docker_audit'
require_relative 'modules/subdomain_scanner'
require_relative 'modules/cve_scanner'
require_relative 'modules/nmap_audit'
require_relative 'modules/service_monitor_audit'

class SecurityAuditCLI
  MENU_OPTIONS = {
    '1' => ['Deteccao basica de rootkits', Modules::RootkitAudit],
    '2' => ['Status do Fail2Ban', Modules::Fail2BanAudit],
    '3' => ['Deteccao basica de crypto miners', Modules::MinerAudit],
    '4' => ['Verificacao de Docker vulneravel', Modules::DockerAudit],
    '5' => ['Scanner de subdominios', Modules::SubdomainScanner],
    '6' => ['Scanner basico de CVEs', Modules::CVEScanner],
    '7' => ['Integracao com Nmap', Modules::NmapAudit],
    '8' => ['Monitoramento de servico systemd', Modules::ServiceMonitorAudit],
    '9' => ['Sair', nil]
  }.freeze

  def run
    setup_output
    menu_loop
  rescue Interrupt
    @output&.line
    @output&.status('Sessao interrompida pelo usuario', :warn)
  ensure
    finish
  end

  private

  def setup_output
    print 'Salvar logs da sessao em ./logs? [s/N]: '
    answer = $stdin.gets&.chomp
    @output = Utils::Output.new(log_enabled: Utils::Validators.yes?(answer))
    @output.banner('Auditoria Defensiva para Debian 12')
    @output.line('Ferramenta educativa de triagem local e auditoria defensiva.')
    @output.line('Use Nmap apenas em alvos autorizados.')
  end

  def menu_loop
    loop do
      print_menu
      choice = @output.prompt('Escolha uma opcao:')
      break if choice == '9'

      execute_choice(choice)
      wait_for_return
    end
  end

  def print_menu
    @output.section('Menu Principal')
    MENU_OPTIONS.each do |key, (label, _)|
      @output.line("#{key}. #{label}")
    end
  end

  def execute_choice(choice)
    option = MENU_OPTIONS[choice]
    unless option
      @output.status('Opcao invalida', :warn, 'selecione um numero entre 1 e 9')
      return
    end

    _label, handler = option
    handler.new(@output).run
  end

  def wait_for_return
    @output.line
    @output.prompt('Pressione ENTER para voltar ao menu...')
  end

  def finish
    return unless @output

    @output.section('Sessao encerrada')
    if @output.log_enabled?
      @output.status('Log salvo', :info, @output.log_path)
    else
      @output.status('Log em arquivo', :info, 'desabilitado nesta sessao')
    end
  end
end

SecurityAuditCLI.new.run
