# frozen_string_literal: true

require 'time'
require_relative 'shell'

module Utils
  class ServiceMonitorError < StandardError; end

  class ServiceSnapshot
    attr_reader :service, :active_state, :sub_state, :main_pid, :exec_main_status,
                :restarts, :memory_current, :cpu_usage_nsec, :load_state,
                :unit_file_state, :fragment_path, :captured_at

    def initialize(service:, properties:)
      @service = service
      @active_state = properties.fetch('ActiveState', 'unknown')
      @sub_state = properties.fetch('SubState', 'unknown')
      @main_pid = properties.fetch('MainPID', '0').to_i
      @exec_main_status = properties.fetch('ExecMainStatus', '0').to_i
      @restarts = properties.fetch('NRestarts', '0').to_i
      @memory_current = parse_integer(properties['MemoryCurrent'])
      @cpu_usage_nsec = parse_integer(properties['CPUUsageNSec'])
      @load_state = properties.fetch('LoadState', 'unknown')
      @unit_file_state = properties.fetch('UnitFileState', 'unknown')
      @fragment_path = properties.fetch('FragmentPath', '')
      @captured_at = Time.now
    end

    def active?
      active_state == 'active' && sub_state == 'running'
    end

    def state_label
      "#{active_state}/#{sub_state}"
    end

    private

    def parse_integer(value)
      stripped = value.to_s.strip
      return nil if stripped.empty? || stripped == '[not set]'

      stripped.to_i
    end
  end

  class ServiceMonitor
    DEFAULT_SERVICE = 'omni-backend.service'
    DEFAULT_INTERVAL = 5
    DEFAULT_LINES = 20
    UNIT_NAME_REGEX = /\A(?!-)[A-Za-z0-9:_.@\\-]+\z/

    def initialize(service:, interval: DEFAULT_INTERVAL, lines: DEFAULT_LINES, emitter: nil)
      @service = normalize_service_name(service)
      @interval = interval
      @lines = lines
      @emitter = emitter || $stdout.method(:puts)
      @last_snapshot = nil
      @stop_requested = false
    end

    def run(once: false)
      ensure_binary!('systemctl')
      ensure_binary!('journalctl')

      last_health = true

      until @stop_requested
        snapshot = capture_snapshot
        emit(summary_line(snapshot))
        report_changes(snapshot)
        last_health = snapshot.active?
        @last_snapshot = snapshot

        break if once

        sleep_with_interrupt(@interval)
      end

      last_health
    end

    def request_stop
      @stop_requested = true
    end

    private

    def ensure_binary!(binary)
      return if Utils::Shell.which(binary)

      raise ServiceMonitorError, "Binario obrigatorio nao encontrado no PATH: #{binary}"
    end

    def sleep_with_interrupt(seconds)
      started_at = Time.now
      while (Time.now - started_at) < seconds
        break if @stop_requested

        sleep 0.2
      end
    end

    def capture_snapshot
      command = Utils::Shell.build(
        'systemctl',
        'show',
        '--property=ActiveState,SubState,MainPID,ExecMainStatus,NRestarts,MemoryCurrent,CPUUsageNSec,LoadState,UnitFileState,FragmentPath',
        '--no-pager',
        '--',
        @service
      )

      result = Utils::Shell.run(command, timeout: 10)
      raise ServiceMonitorError, "Falha ao consultar #{@service}: #{result.output}" unless result.success?

      properties = parse_properties(result.stdout)
      raise ServiceMonitorError, "Servico nao encontrado: #{@service}" if properties['LoadState'] == 'not-found'

      ServiceSnapshot.new(service: @service, properties: properties)
    end

    def parse_properties(raw_output)
      raw_output.each_line.with_object({}) do |line, properties|
        key, value = line.strip.split('=', 2)
        next if key.to_s.empty?

        properties[key] = value.to_s
      end
    end

    def summary_line(snapshot)
      timestamp = snapshot.captured_at.strftime('%Y-%m-%d %H:%M:%S %:z')
      parts = []
      parts << "[#{timestamp}]"
      parts << snapshot.service
      parts << snapshot.state_label
      parts << "pid=#{snapshot.main_pid.zero? ? '-' : snapshot.main_pid}"
      parts << "restarts=#{snapshot.restarts}"
      parts << "mem=#{format_bytes(snapshot.memory_current)}"
      parts << "cpu=#{format_duration(snapshot.cpu_usage_nsec)}"
      parts.join(' ')
    end

    def report_changes(snapshot)
      if @last_snapshot.nil?
        return print_failure_context(snapshot) unless snapshot.active?

        return
      end

      if snapshot.restarts > @last_snapshot.restarts
        emit("Reinicio detectado: #{@last_snapshot.restarts} -> #{snapshot.restarts}")
        print_recent_logs
        return
      end

      state_changed = snapshot.state_label != @last_snapshot.state_label
      pid_changed = snapshot.main_pid != @last_snapshot.main_pid

      return unless state_changed || pid_changed

      emit("Mudanca detectada: #{@last_snapshot.state_label} (pid=#{display_pid(@last_snapshot.main_pid)}) -> #{snapshot.state_label} (pid=#{display_pid(snapshot.main_pid)})")
      print_failure_context(snapshot)
    end

    def print_failure_context(snapshot)
      return if snapshot.active?

      emit("Servico fora do estado esperado. ExecMainStatus=#{snapshot.exec_main_status} UnitFileState=#{snapshot.unit_file_state}")
      print_recent_errors
      print_recent_logs
    end

    def print_recent_errors
      emit('-- erros recentes --')
      print_command_output(
        Utils::Shell.build('journalctl', '-u', @service, '-p', 'err', '-n', @lines, '--no-pager')
      )
    end

    def print_recent_logs
      emit('-- logs recentes --')
      print_command_output(
        Utils::Shell.build('journalctl', '-u', @service, '-n', @lines, '--no-pager')
      )
    end

    def print_command_output(command)
      result = Utils::Shell.run(command, timeout: 15)
      output = result.output
      emit(output.empty? ? '(sem saida)' : output)
    end

    def display_pid(pid)
      pid.to_i.zero? ? '-' : pid
    end

    def format_bytes(bytes)
      return '-' if bytes.nil? || bytes.negative?

      units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
      value = bytes.to_f
      unit = units.shift

      until value < 1024 || units.empty?
        value /= 1024.0
        unit = units.shift
      end

      return format('%.0f %s', value, unit) if value >= 100
      return format('%.1f %s', value, unit) if value >= 10

      format('%.2f %s', value, unit)
    end

    def format_duration(nanoseconds)
      return '-' if nanoseconds.nil? || nanoseconds.negative?

      seconds = nanoseconds / 1_000_000_000.0
      return format('%.0fs', seconds) if seconds >= 100
      return format('%.1fs', seconds) if seconds >= 10

      format('%.2fs', seconds)
    end

    def emit(text)
      @emitter.call(text)
    end

    def normalize_service_name(value)
      normalized = value.to_s.strip
      if normalized.empty? || !normalized.match?(UNIT_NAME_REGEX)
        raise ServiceMonitorError,
              'Nome de servico invalido. Informe apenas a unit do systemd, por exemplo: omni-backend.service'
      end

      normalized
    end
  end
end
