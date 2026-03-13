# frozen_string_literal: true

require 'resolv'

module Utils
  module Validators
    DOMAIN_REGEX = /\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z/i
    HOST_REGEX = /\A[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?\z/
    IPV4_REGEX = /\A(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\z/
    PORT_LIST_REGEX = /\A\d+(?:,\d+)*\z/
    YES_VALUES = %w[s sim y yes].freeze

    module_function

    def yes?(value, default: false)
      normalized = value.to_s.strip.downcase
      return default if normalized.empty?

      YES_VALUES.include?(normalized)
    end

    def domain?(value)
      normalized = value.to_s.strip.downcase
      normalized.match?(DOMAIN_REGEX)
    end

    def host_or_ipv4?(value)
      normalized = value.to_s.strip
      return true if normalized == 'localhost'

      normalized.match?(IPV4_REGEX) || normalized.match?(HOST_REGEX)
    end

    def port_list?(value)
      value.to_s.strip.match?(PORT_LIST_REGEX)
    end

    def resolve(host)
      Resolv.getaddresses(host).uniq
    rescue Resolv::ResolvError
      []
    end
  end
end
