module OpenIDConnect
  module Discovery
    module Provider
      class Config
        def self.discover!(issuer, discovery_uri = "", cache_options = {})
          # Some identity providers (AAD) don't implement the discovery URI using the standard and append additional query
          # string parameters. By allowing configuration of both of these values we can support both compliant and partial
          # compliant implementations.
          discovery_uri = issuer if discovery_uri.empty?
          uri = URI.parse(discovery_uri)
          Resource.new(uri).discover!(cache_options).tap do |response|
            response.expected_issuer = issuer
            response.validate!
          end
        rescue SWD::Exception, ValidationFailed => e
          raise DiscoveryFailed.new(e.message)
        end
      end
    end
  end
end

require 'openid_connect/discovery/provider/config/resource'
require 'openid_connect/discovery/provider/config/response'