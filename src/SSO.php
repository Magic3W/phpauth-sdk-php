<?php namespace magic3w\phpauth\sdk;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Utils;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\UnencryptedToken;
use spitfire\io\request\Request;
use magic3w\http\url\reflection\URLReflection;
use spitfire\exceptions\user\ApplicationException;

class SSO
{
	
	/**
	 * This client will be in charge of sending our requests to the server.
	 * 
	 * The change to guzzle is requiring us to reconsider the way we handle HTTP requests,
	 * previously we would have used this class to create a request and have the applications
	 * relying on it change the request as needed.
	 * 
	 * This is currently not available, since Guzzle requires the client object to be
	 * used in tandem with the request objects.
	 * 
	 * @var Client
	 */
	private $client;
	
	/**
	 * 
	 * @var string
	 */
	private $endpoint;
	
	/**
	 * 
	 * @var int
	 */
	private $appId;
	
	/**
	 * 
	 * @var string
	 */
	private $appSecret;
	
	/**
	 * 
	 * @var Configuration
	 */
	private $jwt;
	
	/**
	 * 
	 * @param string $credentials
	 */
	public function __construct(string $credentials) 
	{
		$reflection = URLReflection::fromURL($credentials);
		$path = $reflection->getPath();
		$host = $reflection->getProtocol() . '://' . $reflection->getHostname() . ':' . $reflection->getPort();
		
		$this->endpoint  = rtrim($host . $path, '/');
		$this->appId     = (int)$reflection->getUser();
		$this->appSecret = $reflection->getPassword();
		
		if (!$this->appSecret) {
			throw new Exception('App Secret is missing', 1807021658);
		}
		
		$this->client = new Client(['base_uri' => $this->endpoint]);
		$this->jwt = Configuration::forSymmetricSigner(new Sha256, InMemory::base64Encoded($this->appSecret));
	}
	
	/**
	 * Generates a URL to direct the user agent to in order to initiate
	 * the authentication. Please note that the oAuth 2.0 protocol uses the user
	 * agent for this 'request', therefore the server itself is not performing 
	 * the request at all.
	 * 
	 * I would like to avoid using the word request for whatever is happening
	 * at this stage of the connection.
	 * 
	 * @param string $state
	 * @param string $verifier_challenge
	 * @param string $returnto
	 * @param int|null $audience The app ID of the application this client wishes to access data from. This may
	 *        be null if the application wishes to access the client account on PHPAS.
	 * @return string
	 */
	public function makeAccessCodeRedirect(
		string $state, 
		string $verifier_challenge, 
		string $returnto, 
		int $audience = null
	) : string {
		
		$query = [
			'response_type' => 'code',
			'client' => $this->appId,
			'audience' => (string)$audience,
			'state' => $state,
			'redirect' => $returnto,
			'code_challenge' => hash('sha256', $verifier_challenge),
			'code_challenge_method' => 'S256'
		];
		
		$request = URLReflection::fromURL(sprintf('%s/auth/oauth', $this->endpoint));
		$request->setQueryString($query);
		
		return strval($request);
	}
	
	/**
	 * Tokens can be retrieved using three different mechanisms.
	 * 
	 * 1. Provide an access code that a user generated. This is used during the oAuth flow
	 * 2. Provide application specific credentials, yields a client token
	 * 3. Provide a refresh token.
	 * 
	 * This mechanism intends to make it simple for the applications to generate new tokens
	 * for the first scenario, by providing a code and a verifier to the table.
	 * 
	 * @param string $code
	 * @param string $verifier
	 * @param int|null $audience
	 * @return array{'access': Token, 'refresh': RefreshToken}
	 */
	public function token(string $code, string $verifier, int $audience = null) : array
	{
		$post = [
			['name' => 'type', 'contents' => 'code'],
			['name' => 'code', 'contents' => $code],
			['name' => 'client', 'contents' => (string)$this->getAppId()],
			['name' => 'audience', 'contents' => (string)$audience],
			['name' => 'secret', 'contents' => $this->appSecret],
			['name' => 'verifier', 'contents' => $verifier]
		];
		
		$response = $this->request('/token/create.json', $post);
		
		/**
		 * These assertions are only executed in a development environment, allowing servers running
		 * in production to ignore these and assume that the response they received from the other 
		 * party is safe.
		 */
		assert(is_object($response) && isset($response->tokens));
		assert($response->tokens->access && $response->tokens->access->token);
		assert($response->tokens->refresh && $response->tokens->refresh->token);
		
		$access = $response->tokens->access;
		$parsed = $this->jwt->parser()->parse($access->token);
		
		assert($parsed instanceof UnencryptedToken);
		
		return [
			'access'  => new Token($this, $parsed, $access->expires),
			'refresh' => new RefreshToken($this, $response->tokens->refresh->token, $response->tokens->refresh->expires)
		];
	}
	
	/**
	 * Refreshes an access and refresh token by passing a refresh token to the 
	 * system as grant.
	 * 
	 * The token must be a string, if you held onto the `Token` object you received
	 * from the API, you can extract the code by calling getToken.
	 * 
	 * @param string $token
	 * @return array{'access': Token, 'refresh': RefreshToken}
	 */
	public function refresh(string $token) : array
	{
		return $this->renew(new RefreshToken($this, $token, null));
	}
	
	/**
	 * Returns an access token that allows the application to access it's own credentials
	 * on the server.
	 * 
	 * @param int|null $audience
	 * @return Token
	 */
	public function credentials(int $audience = null) 
	{
		
		$post = [
			['name' => 'type', 'contents' => 'client_credentials'],
			['name' => 'client', 'contents' => (string)$this->getAppId()],
			['name' => 'audience', 'contents' => (string)$audience],
			['name' => 'secret', 'contents' => $this->appSecret],
		];
		
		$response = $this->request('/token/create.json', $post);
		
		/**
		 * These assertions are only executed in a development environment, allowing servers running
		 * in production to ignore these and assume that the response they received from the other 
		 * party is safe.
		 */
		assert(is_object($response) && isset($response->tokens));
		assert($response->tokens->access && $response->tokens->access->token);
		
		return new Token($this, $response->tokens->access->token, $response->tokens->access->expires);
	}
	
	/**
	 * The base URL of the PHPAuth Server
	 * 
	 * @return string
	 */
	public function getEndpoint() : string
	{
		return $this->endpoint;
	}
	
	/**
	 * The app id of the application that is authenticating this client.
	 * 
	 * @return int
	 */
	public function getAppId() : int
	{
		return $this->appId;
	}
	
	/**
	 * Returns the secret the system is using to communicate with the server. This can be
	 * used by refresh tokens to renew their lease.
	 * 
	 * @return string
	 */
	public function getSecret()
	{
		return $this->appSecret;
	}
	
	/**
	 * 
	 * @return object
	 */
	public function getGroupList() : object
	{
		$resp = $this->request('/group/index.json');
		assert(isset($resp->payload));
		return $resp->payload;
	}
	
	/**
	 * 
	 * @param string $id
	 * @return object
	 */
	public function getGroup(string $id) : object
	{
		$resp = $this->request('/group/detail/' . $id . '.json');
		assert(isset($resp->payload));
		return $resp->payload;
	}
	
	
	/**
	 * This method allows your client to push a custom scope onto the server. This scope
	 * can then be used by third party applications to request access to parts of the user's
	 * data that you requested be fenced off.
	 * 
	 * @param string $id
	 * @param string $name
	 * @param string $description
	 * @param string $icon
	 * @return void
	 */
	public function putScope($id, $name, $description, $icon = null) : void
	{
		$post = [
			['name' => 'token', 'contents' => (string)$this->credentials()->getId()],
			['name' => 'name', 'contents' => $name],
			['name' => 'description', 'contents' => $description],
			['name' => 'icon', 'contents' => Utils::tryFopen($icon, 'r'), 'filename' => basename($icon)]
		];
		
		$this->request(sprintf('/scope/create/%s.json', $id), $post);
	}
	
	/**
	 * Generate a logout link. The logout flow is best described as follows:
	 * 
	 * 1. Client generates a logout link, which contains a return URL to direct the user to on successful logout
	 * 2. Resource owner is directed to the logout location
	 * 3. Authentication server terminates the session, and all authenticated tokens that depend on it
	 * 4. Authentication directs the resource owner to the return URL
	 * 5. Client destroys the session on their end.
	 * 
	 * Alternatively, the client can execute the 5fth point first.
	 * 
	 * Asynchronously, the Authentication server will start notifying all applications
	 * using tokens in the current session to destroy them. 
	 * 
	 * Invoking this endpoint is optional, it only ends the session on the authentication
	 * server, allowing your application to display a "log out" from all 
	 * 
	 * @param Token $token
	 * @param string $returnto
	 * @return string
	 */
	public function getLogoutLink(Token $token, string $returnto) : string
	{
		$query = http_build_query(['returnto' => $returnto, 'token' => $token->getId()]);
		return $this->endpoint . '/user/logout?' . $query;
	}
	
	
	/**
	 * The renew method 
	 * 
	 * @param RefreshToken $token
	 * @return array{'access': Token, 'refresh': RefreshToken}
	 */
	public function renew(RefreshToken $token) : array
	{	
		$post = [
			['name' => 'type', 'contents' => 'code'],
			['name' => 'token', 'contents' => $token->getId()],
			['name' => 'client', 'contents' => (string)$this->getAppId()],
			['name' => 'secret', 'contents' => $this->getSecret()]
		];
		
		$response = $this->request('/token/create.json', $post);
		
		/**
		 * These assertions are only executed in a development environment, allowing servers running
		 * in production to ignore these and assume that the response they received from the other 
		 * party is safe.
		 */
		assert(is_object($response) && isset($response->tokens));
		assert($response->tokens->access && $response->tokens->access->token);
		assert($response->tokens->refresh && $response->tokens->refresh->token);
		
		$access = $response->tokens->access;
		$parsed = $this->jwt->parser()->parse($access->token);
		
		assert($parsed instanceof UnencryptedToken);
		
		return [
			'access'  => new Token($this, $parsed, $access->expires),
			'refresh' => new RefreshToken($this, $response->tokens->refresh->token, $response->tokens->refresh->expires)
		];
	}
	
	/**
	 * Prepares a authenticated request that all objects can use to interact with
	 * the API.
	 * 
	 * @param string $url
	 * @param mixed[][] $payload
	 * @param string[] $query
	 * @param string[] $headers
	 * @return object The raw response from the server (JSON decoded).
	 */
	private function request($url, array $payload = [], array $query = [], array $headers = []) : object
	{
		/**
		 * Send a request to the server and harvest the response.
		 */
		$response = $this->client->post(
			$url,
			[
				'headers' => $headers, 
				'multipart' => $payload,
				'query' => $query
			]
		);
		
		/**
		 * With a bad status code, the application should not proceed. This means that the server ran into a 
		 * special condition that we did not anticipate and that we need to handle since it's outside
		 * the scope of the client.
		 * 
		 * @todo Introduce special SSO Network exception type
		 */
		if ($response->getStatusCode() !== 200) {
			throw new ApplicationException(
				'The authentication server replied with an invalid response code', 
				$response->getStatusCode()
			);
		}
		
		/**
		 * Parse the server's response. Please note that the server will ALWAYS reply to API requests with
		 * valid json. If this is not the case, the request went wrong or the server is misconfigured.
		 * 
		 * This means that we cannot continue with the execution.
		 */
		$responsePayload = json_decode((string)$response->getBody());
		
		if (json_last_error() !== JSON_ERROR_NONE) {
			throw new ApplicationException('The server replied with malformed JSON', 2107071256);
		}
		
		return $responsePayload;
	}
}
