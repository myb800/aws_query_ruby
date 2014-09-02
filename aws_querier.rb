require "openssl"
require "Base64"
require "digest"
require "net/https"
require "uri"


class AwsQuerier

  def initialize(access_key,secret_key)
    @access_key = access_key
    @secret_key = secret_key
  end

  def getResponse(opt={})
    # opt should have these keys
    # :method,:service,:uri,:region,:endpoint,:init_header,:canonical_querystring<-should be urlencoded,:payload
    # :signed_headers
    net_http_klass = getNetHTTPClass opt[:method]
    request_url = opt[:endpoint]
    request_url = "#{request_url}?#{opt[:canonical_querystring]}" unless opt[:canonical_querystring]==""
    uri = URI.parse(request_url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    request = net_http_klass.new(uri.request_uri,getAuthorizationHeader(opt))
    request.body=opt[:payload]
    response = http.request(request)
  end
  private
  def sign(key,msg)
    OpenSSL::HMAC.digest(OpenSSL::Digest.new("sha256"), key, msg).strip
  end

  def getSignatureKey(key, dateStamp, regionName, serviceName)
    kDate = sign(("AWS4" + key).encode("utf-8"), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, "aws4_request")
  end

  def getHexDigestSHA256(msg)
    Digest::SHA256.hexdigest msg
  end

  def getNetHTTPClass(method)
    case method.downcase
      when "get"
        return Net::HTTP::Get
      when "post"
        return Net::HTTP::Post
    end
  end

  def getAuthorizationHeader(opt={})
    t = Time.now.utc
    uri = URI.parse(opt[:uri])
    host = uri.host
    canonical_uri = uri.path==""?"/":uri.path

    # time
    amzdate = t.strftime("%Y%m%dT%H%M%SZ")
    datestamp = t.strftime("%Y%m%d")

    headers = {"host"=>host,"x-amz-date"=>amzdate}
    opt[:init_header].each do |k,v|
      headers.merge!(k=>v)
    end

    # Step 1 is to define the verb (GET, POST, etc.)
    method = opt[:method].upcase

    # Step 2: Create canonical URI
    # Step 3: Create the canonical query string
      canonical_querystring = opt[:canonical_querystring]

    # Step 4: Create the canonical headers and signed headers.
    canonical_headers = headers.keys.sort.map{|e| "#{e}:#{headers[e]}"}.join("\n") + "\n"

    # Step 5: Create the list of signed headers.
    signed_headers = opt[:signed_headers].split(";").sort.join(";")

    # Step 6: Create payload hash
    payload_hash = getHexDigestSHA256(opt[:payload])

    # Step 7: Combine elements to create create canonical request
    canonical_request = method + "\n" + canonical_uri + "\n" + canonical_querystring + "\n" + canonical_headers + "\n" + signed_headers + "\n" + payload_hash

    # ************* TASK 2: CREATE THE STRING TO SIGN*************
    # Match the algorithm to the hashing algorithm you use, either SHA-1 or
    # SHA-256 (recommended)
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = datestamp + "/" + opt[:region] + "/" + opt[:service] + "/" + "aws4_request"
    string_to_sign = algorithm + "\n" +  amzdate + "\n" +  credential_scope + "\n" +getHexDigestSHA256(canonical_request)

    # ************* TASK 3: CALCULATE THE SIGNATURE *************
    signing_key = getSignatureKey(@secret_key, datestamp, opt[:region], opt[:service])
    signature = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new("sha256"), signing_key, string_to_sign.encode("utf-8"))

    # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
    authorization_header = algorithm + " " + "Credential=" + @access_key + "/" + credential_scope + ", " +  "SignedHeaders=" + signed_headers + ", " + "Signature=" + signature
    headers.merge!("authorization"=>authorization_header)

    headers
  end

end

request_parameters =  '{'
request_parameters +=  '"KeySchema": [{"KeyType": "HASH","AttributeName": "Id"}],'
request_parameters +=  '"TableName": "TestTable3","AttributeDefinitions": [{"AttributeName": "Id","AttributeType": "S"}],'
request_parameters +=  '"ProvisionedThroughput": {"WriteCapacityUnits": 5,"ReadCapacityUnits": 5}'
request_parameters +=  '}'

access_key = "access_key"
secret_key = "secret_key"

response = AwsQuerier.new(access_key,secret_key).getResponse(
    method:"post",
    service:"dynamodb",
    uri:"https://dynamodb.us-east-1.amazonaws.com/",
    region:"us-east-1",
    endpoint:"https://dynamodb.us-east-1.amazonaws.com/",
    init_header:{"content-type"=>"application/x-amz-json-1.0","x-amz-target"=>"DynamoDB_20120810.CreateTable"},
    canonical_querystring:"",
    payload:request_parameters,
    signed_headers:"content-type;host;x-amz-date;x-amz-target")
response