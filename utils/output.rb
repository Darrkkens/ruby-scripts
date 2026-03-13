# frozen_string_literal: true

module Utils
  class Output
    ANSI_CODES = {
      reset: 0,
      bold: 1,
      red: 31,
      green: 32,
      yellow: 33,
      blue: 34,
      cyan: 36
    }.freeze

    attr_reader :log_path

    def initialize(log_enabled: false, log_dir: 'logs', color: $stdout.tty?)
      @log_enabled = log_enabled
      @color = color
      return unless @log_enabled

      Dir.mkdir(log_dir) unless Dir.exist?(log_dir)
      @log_path = File.join(log_dir, "audit-#{Time.now.strftime('%Y%m%d-%H%M%S')}.log")
      File.write(@log_path, "# Auditoria defensiva\n# Gerado em #{Time.now}\n\n")
    end

    def log_enabled?
      @log_enabled
    end

    def banner(title)
      line(colorize(title, :bold))
      line(colorize('-' * title.length, :blue))
    end

    def section(title)
      line
      line(colorize("== #{title} ==", :cyan))
    end

    def status(label, level, detail = nil)
      tag = level.to_s.upcase
      color = case level
              when :ok then :green
              when :warn then :yellow
              when :error then :red
              else :blue
              end

      message = "[#{colorize(tag, color)}] #{label}"
      message = "#{message}: #{detail}" unless detail.to_s.strip.empty?
      line(message)
    end

    def item(text)
      line(" - #{text}")
    end

    def key_value(key, value)
      line(format('%-24s %s', "#{key}:", value))
    end

    def prompt(text)
      print "#{text} "
      answer = $stdin.gets&.chomp.to_s
      log("PROMPT #{text}")
      log("INPUT #{answer}")
      answer
    end

    def divider
      line(colorize('-' * 60, :blue))
    end

    def line(text = '')
      content = text.to_s
      puts content
      log(strip_ansi(content))
    end

    private

    def log(text)
      return unless @log_enabled

      File.open(@log_path, 'a') { |file| file.puts(text) }
    end

    def colorize(text, color)
      return text unless @color

      "\e[#{ANSI_CODES[color]}m#{text}\e[#{ANSI_CODES[:reset]}m"
    end

    def strip_ansi(text)
      text.gsub(/\e\[[\d;]*m/, '')
    end
  end
end
