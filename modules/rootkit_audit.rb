# frozen_string_literal: true

module Modules
  class RootkitAudit
    COMMON_PACKAGES = %w[
      bash
      coreutils
      procps
      login
      passwd
      openssh-client
      openssh-server
      sudo
      iproute2
    ].freeze

    TEMP_DIRECTORIES = %w[/tmp /var/tmp /dev/shm].freeze

    def initialize(output)
      @output = output
    end

    def run
      @output.section('Deteccao basica de rootkits')
      @output.line('Escopo: integracao com ferramentas locais e busca por sinais simples de ocultacao ou adulteracao.')

      run_rkhunter
      run_chkrootkit
      verify_common_binaries
      check_deleted_binaries
      check_hidden_executables
    end

    private

    def run_rkhunter
      unless Utils::Shell.which('rkhunter')
        @output.status('rkhunter', :info, 'nao instalado; opcional para verificacao mais ampla')
        return
      end

      result = Utils::Shell.run('rkhunter --check --sk --nocolors', timeout: 180)
      warnings = result.stdout.lines.grep(/warning|suspect/i).map(&:strip).uniq

      if warnings.empty? && result.success?
        @output.status('rkhunter', :ok, 'sem alertas destacados no modo rapido')
      elsif warnings.empty?
        @output.status('rkhunter', :warn, result.output)
      else
        @output.status('rkhunter', :warn, "#{warnings.size} alerta(s) destacado(s)")
        warnings.first(8).each { |line| @output.item(line) }
      end
    end

    def run_chkrootkit
      unless Utils::Shell.which('chkrootkit')
        @output.status('chkrootkit', :info, 'nao instalado; opcional para verificacao complementar')
        return
      end

      result = Utils::Shell.run('chkrootkit -q', timeout: 180)
      findings = result.stdout.lines.map(&:strip).reject(&:empty?).uniq

      if findings.empty? && result.success?
        @output.status('chkrootkit', :ok, 'sem alertas em modo silencioso')
      elsif findings.empty?
        @output.status('chkrootkit', :warn, result.output)
      else
        @output.status('chkrootkit', :warn, "#{findings.size} sinal(is) suspeito(s)")
        findings.first(10).each { |line| @output.item(line) }
      end
    end

    def verify_common_binaries
      unless Utils::Shell.which('debsums')
        @output.status('Integridade de binarios', :info, 'instale `debsums` para verificar pacotes do sistema')
        return
      end

      command = "debsums -s #{COMMON_PACKAGES.join(' ')}"
      result = Utils::Shell.run(command, timeout: 120)
      findings = [result.stdout, result.stderr].join("\n").lines.map(&:strip).reject(&:empty?).uniq

      if findings.empty?
        @output.status('Integridade de binarios', :ok, 'sem divergencias nos pacotes monitorados')
      else
        @output.status('Integridade de binarios', :warn, 'arquivos alterados ou sem hash conhecido')
        findings.first(10).each { |line| @output.item(line) }
      end
    end

    def check_deleted_binaries
      unless Utils::Shell.which('lsof')
        @output.status('Arquivos deletados ainda em uso', :info, 'instale `lsof` para ampliar a triagem')
        return
      end

      result = Utils::Shell.run('lsof +L1 2>/dev/null | sed -n "2,12p"', timeout: 30)
      findings = result.stdout.lines.map(&:strip).reject(&:empty?)

      if findings.empty?
        @output.status('Arquivos deletados ainda em uso', :ok, 'nenhum processo com arquivo apagado destacado')
      else
        @output.status('Arquivos deletados ainda em uso', :warn, "#{findings.size} entrada(s) destacada(s)")
        findings.each { |line| @output.item(line) }
      end
    end

    def check_hidden_executables
      command = 'find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 2>/dev/null | sed -n "1,12p"'
      result = Utils::Shell.run(command, timeout: 45)
      findings = result.stdout.lines.map(&:strip).reject(&:empty?)

      if findings.empty?
        @output.status('Executaveis em diretorios temporarios', :ok, 'nenhum executavel destacado em /tmp, /var/tmp ou /dev/shm')
      else
        @output.status('Executaveis em diretorios temporarios', :warn, "#{findings.size} caminho(s) destacado(s)")
        findings.each { |line| @output.item(line) }
      end
    end
  end
end
