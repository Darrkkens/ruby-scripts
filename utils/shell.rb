# frozen_string_literal: true

require 'open3'
require 'shellwords'

module Utils
  CommandResult = Struct.new(:command, :stdout, :stderr, :status, keyword_init: true) do
    def success?
      !status.nil? && status.success?
    end

    def exit_code
      status&.exitstatus
    end

    def output
      [stdout.to_s.strip, stderr.to_s.strip].reject(&:empty?).join("\n")
    end
  end

  module Shell
    module_function

    def which(binary)
      return binary if binary.include?(File::SEPARATOR) && File.executable?(binary)

      ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).each do |path|
        candidate = File.join(path, binary)
        return candidate if File.executable?(candidate) && !File.directory?(candidate)
      end

      nil
    end

    def build(*parts)
      parts.flatten.compact.map { |part| Shellwords.escape(part.to_s) }.join(' ')
    end

    def run(command, timeout: 30)
      stdout = +''
      stderr = +''
      status = nil

      Open3.popen3('/bin/bash', '-lc', command) do |stdin, out, err, wait_thr|
        stdin.close

        stdout_thread = Thread.new { stdout = out.read.to_s }
        stderr_thread = Thread.new { stderr = err.read.to_s }

        if wait_thr.join(timeout)
          stdout_thread.join
          stderr_thread.join
          status = wait_thr.value
        else
          Process.kill('TERM', wait_thr.pid) rescue nil
          sleep 0.2
          Process.kill('KILL', wait_thr.pid) rescue nil
          stdout_thread.join(1)
          stderr_thread.join(1)

          return CommandResult.new(
            command: command,
            stdout: stdout,
            stderr: "Tempo limite excedido apos #{timeout}s",
            status: nil
          )
        end
      end

      CommandResult.new(command: command, stdout: stdout, stderr: stderr, status: status)
    rescue StandardError => e
      CommandResult.new(command: command, stdout: stdout, stderr: e.message, status: nil)
    end
  end
end
