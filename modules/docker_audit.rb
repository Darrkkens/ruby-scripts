# frozen_string_literal: true

require 'etc'
require 'json'

module Modules
  class DockerAudit
    SENSITIVE_HOST_PORTS = %w[22 2375 2376 3306 5432 6379 27017 9200 5601].freeze
    HIGH_RISK_CAPS = %w[ALL SYS_ADMIN SYS_PTRACE NET_ADMIN DAC_READ_SEARCH].freeze
    CRITICAL_PATHS = %w[/ /etc /root /home /proc /sys /var/run/docker.sock].freeze

    def initialize(output)
      @output = output
    end

    def run
      @output.section('Verificacao de Docker vulneravel')

      unless Utils::Shell.which('docker') || File.exist?('/etc/docker/daemon.json')
        @output.status('Docker', :error, 'nao instalado neste host')
        return
      end

      @output.status('Docker', :ok, 'cli ou configuracao do daemon detectada')
      check_service_state
      check_daemon_exposure
      check_socket_permissions
      inspect_running_containers
    end

    private

    def check_service_state
      active = Utils::Shell.run('systemctl is-active docker', timeout: 15).stdout.strip
      enabled = Utils::Shell.run('systemctl is-enabled docker', timeout: 15).stdout.strip

      @output.status('Daemon ativo', active == 'active' ? :ok : :warn, active.empty? ? 'nao foi possivel consultar o systemd' : active)
      @output.status('Inicio automatico', enabled == 'enabled' ? :ok : :info, enabled.empty? ? 'nao foi possivel consultar o systemd' : enabled)
    end

    def check_daemon_exposure
      configured_hosts = []

      if File.exist?('/etc/docker/daemon.json')
        begin
          daemon_config = JSON.parse(File.read('/etc/docker/daemon.json'))
          configured_hosts = Array(daemon_config['hosts']).map(&:to_s)
        rescue JSON::ParserError => e
          @output.status('daemon.json', :warn, "arquivo invalido: #{e.message}")
        end
      else
        @output.status('daemon.json', :info, 'arquivo nao encontrado; usando defaults do pacote')
      end

      exposed_config = configured_hosts.select { |host| host.include?('tcp://') }
      if exposed_config.empty?
        @output.status('Hosts configurados no daemon', :ok, configured_hosts.empty? ? 'sem hosts TCP explicitos' : configured_hosts.join(', '))
      else
        @output.status('Hosts configurados no daemon', :warn, exposed_config.join(', '))
      end

      ss_result = Utils::Shell.run("ss -lntp 2>/dev/null | grep -E '2375|2376|dockerd'", timeout: 15)
      listeners = ss_result.stdout.lines.map(&:strip).reject(&:empty?)

      if listeners.empty?
        @output.status('Daemon exposto em rede', :ok, 'nenhum listener TCP destacado para Docker')
      else
        @output.status('Daemon exposto em rede', :warn, "#{listeners.size} listener(s) destacado(s)")
        listeners.each { |line| @output.item(line) }
      end
    end

    def check_socket_permissions
      socket_path = '/var/run/docker.sock'
      unless File.exist?(socket_path)
        @output.status('docker.sock', :info, 'socket nao encontrado')
        return
      end

      stat = File.stat(socket_path)
      group = Etc.getgrgid(stat.gid).name rescue stat.gid
      mode = format('%o', stat.mode & 0o777)
      @output.key_value('docker.sock', "#{socket_path} (modo #{mode}, grupo #{group})")

      return unless group == 'docker'

      members_line = Utils::Shell.run('getent group docker', timeout: 10).stdout.strip
      members = members_line.split(':').last.to_s.split(',').map(&:strip).reject(&:empty?)

      if members.empty?
        @output.status('Grupo docker', :info, 'grupo existe sem membros explicitamente listados')
      else
        @output.status('Grupo docker', :warn, "membros possuem acesso equivalente a root: #{members.join(', ')}")
      end
    end

    def inspect_running_containers
      ps_result = Utils::Shell.run("docker ps --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'", timeout: 30)

      unless ps_result.success?
        @output.status('Containers em execucao', :warn, blank_or(ps_result.output, 'nao foi possivel consultar `docker ps`'))
        return
      end

      containers = ps_result.stdout.lines.map do |line|
        id, name, image, status, ports = line.chomp.split("\t", 5)
        next if id.to_s.empty?

        { id: id, name: name, image: image, status: status, ports: ports.to_s }
      end.compact

      if containers.empty?
        @output.status('Containers em execucao', :ok, 'nenhum container ativo')
        return
      end

      @output.status('Containers em execucao', :ok, containers.map { |container| container[:name] }.join(', '))
      containers.each do |container|
        inspect_container(container)
      end
    end

    def inspect_container(container)
      @output.divider
      @output.key_value('Container', "#{container[:name]} (#{container[:id][0, 12]})")
      @output.key_value('Imagem', container[:image])
      @output.key_value('Status', container[:status])
      @output.key_value('Portas publicadas', container[:ports].empty? ? 'nenhuma' : container[:ports])

      inspect_result = Utils::Shell.run("docker inspect #{Utils::Shell.build(container[:id])}", timeout: 45)
      unless inspect_result.success?
        @output.status('Inspecao detalhada', :warn, blank_or(inspect_result.output, 'nao foi possivel inspecionar o container'))
        return
      end

      data = JSON.parse(inspect_result.stdout).first
      findings = []

      findings << { level: :error, message: 'container privilegiado' } if data.dig('HostConfig', 'Privileged')
      findings << { level: :warn, message: 'usa network namespace do host' } if data.dig('HostConfig', 'NetworkMode') == 'host'
      findings << { level: :warn, message: 'compartilha PID namespace do host' } if data.dig('HostConfig', 'PidMode') == 'host'
      findings << { level: :warn, message: 'usuario padrao do container parece root' } if root_container_user?(data)

      caps = Array(data.dig('HostConfig', 'CapAdd'))
      dangerous_caps = caps & HIGH_RISK_CAPS
      findings << { level: :warn, message: "capabilities adicionais: #{dangerous_caps.join(', ')}" } if dangerous_caps.any?

      risky_bindings = published_bindings(data).select do |binding|
        public_binding?(binding[:host_ip]) && SENSITIVE_HOST_PORTS.include?(binding[:host_port].to_s)
      end
      risky_bindings.each do |binding|
        findings << {
          level: :warn,
          message: "porta sensivel publicada publicamente: #{binding[:host_ip]}:#{binding[:host_port]} -> #{binding[:container_port]}"
        }
      end

      critical_mounts(data).each do |mount|
        findings << { level: :warn, message: "mount critico: #{mount}" }
      end

      if findings.empty?
        @output.status('Postura do container', :ok, 'nenhum risco alto destacado nesta verificacao')
      else
        findings.each { |finding| @output.status('Postura do container', finding[:level], finding[:message]) }
      end
    rescue JSON::ParserError => e
      @output.status('Inspecao detalhada', :warn, "saida JSON invalida: #{e.message}")
    end

    def root_container_user?(data)
      user = data.dig('Config', 'User').to_s.strip
      user.empty? || user == '0' || user.start_with?('0:')
    end

    def published_bindings(data)
      ports = data.dig('NetworkSettings', 'Ports') || {}
      bindings = []

      ports.each do |container_port, host_bindings|
        Array(host_bindings).each do |binding|
          bindings << {
            container_port: container_port,
            host_ip: binding['HostIp'].to_s,
            host_port: binding['HostPort'].to_s
          }
        end
      end

      bindings
    end

    def public_binding?(host_ip)
      ['', '0.0.0.0', '::', ':::'].include?(host_ip)
    end

    def critical_mounts(data)
      Array(data['Mounts']).filter_map do |mount|
        source = mount['Source'].to_s
        destination = mount['Destination'].to_s
        next unless critical_path?(source) || critical_path?(destination)

        "#{source} -> #{destination}"
      end
    end

    def critical_path?(path)
      return true if path == '/'

      CRITICAL_PATHS.any? do |critical|
        critical != '/' && path.start_with?(critical)
      end
    end

    def blank_or(value, fallback)
      text = value.to_s.strip
      text.empty? ? fallback : text
    end
  end
end
