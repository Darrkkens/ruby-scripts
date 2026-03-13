# frozen_string_literal: true

require 'rexml/document'

module Utils
  module NmapHelper
    module_function

    def available?
      !Utils::Shell.which('nmap').nil?
    end

    def scan(target, ports: nil, service_detection: false, top_ports: nil, timeout: 120)
      args = ['nmap', '-Pn', '-oX', '-']
      args += ['-sV', '--version-light'] if service_detection

      if ports && !ports.to_s.strip.empty?
        args += ['-p', ports]
      elsif top_ports
        args += ['--top-ports', top_ports.to_s]
      else
        args << '-F'
      end

      args << target
      result = Utils::Shell.run(Utils::Shell.build(args), timeout: timeout)
      return { ok: false, error: blank_or(result.output, 'Falha ao executar nmap'), raw: result } unless result.success?

      parse_xml(result.stdout)
    end

    def parse_xml(xml)
      document = REXML::Document.new(xml)
      hosts = []

      REXML::XPath.each(document, '//host') do |host_node|
        address = host_node.elements["address[@addrtype='ipv4']"]&.attributes&.[]('addr')
        address ||= host_node.elements['address']&.attributes&.[]('addr')

        hostnames = host_node.get_elements('hostnames/hostname').map { |node| node.attributes['name'] }.compact
        ports = host_node.get_elements('ports/port').filter_map do |port_node|
          state = port_node.elements['state']&.attributes&.[]('state')
          next unless state == 'open'

          service = port_node.elements['service']
          {
            protocol: port_node.attributes['protocol'],
            port: port_node.attributes['portid'].to_i,
            state: state,
            name: service&.attributes&.[]('name'),
            product: service&.attributes&.[]('product'),
            version: service&.attributes&.[]('version'),
            extrainfo: service&.attributes&.[]('extrainfo')
          }
        end

        hosts << { address: address, hostnames: hostnames, ports: ports }
      end

      { ok: true, hosts: hosts, raw_xml: xml }
    rescue REXML::ParseException => e
      { ok: false, error: "Falha ao interpretar a saida XML do nmap: #{e.message}" }
    end

    def blank_or(value, fallback)
      text = value.to_s.strip
      text.empty? ? fallback : text
    end
    private_class_method :blank_or
  end
end
