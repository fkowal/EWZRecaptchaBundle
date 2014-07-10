<?php

namespace EWZ\Bundle\RecaptchaBundle\Validator\Constraints;

use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\ValidatorException;

class TrueValidator extends ConstraintValidator {
    const RECAPTCHA_VERIFY_SERVER = 'http://www.google.com';

    protected $container;
    private $url = self::RECAPTCHA_VERIFY_SERVER;
    private $options = array(
        'timeout'=>0.5,
        'connect_timeout'=>0.5,
    );

    /**
     * Construct.
     *
     * @param ContainerInterface $container An ContainerInterface instance
     */
    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
        $this->setClient(null);
    }

    /**
     * {@inheritdoc}
     */
    public function validate($value, Constraint $constraint)
    {
        if (!$this->container->getParameter('ewz_recaptcha.enabled')) {
            return true;
        }

        // define variable for recaptcha check answer
        $privateKey = $this->container->getParameter('ewz_recaptcha.private_key');

        $request = $this->container->get('request');
        $remoteip = $this->getRealIp($request->server);
        $challenge  = $request->get('recaptcha_challenge_field');
        $response   = $request->get('recaptcha_response_field');

        $answer = $this->checkAnswer($privateKey, $remoteip, $challenge, $response);

        if (!$answer) {
            $this->context->addViolation($constraint->message);
        }
    }

    /**
     * @param ParameterBag $server
     *
     * @return string
     */
    protected function getRealIp($server) {
        $remoteip = null;
        if ($server->has('REALIP') ) {
            $remoteip = $server->get('REALIP');
        }
        if (!$remoteip && $server->has('X_REAL_IP') ) {
            $remoteip = $server->get('X_REAL_IP');
        }
        if (!$remoteip ) {
            $remoteip = $server->get('REMOTE_ADDR');
        }
        return $remoteip;
    }

    /**
     * Calls an HTTP POST function to verify if the user's guess was correct
     *
     * @param string $privateKey
     * @param string $remoteip
     * @param string $challenge
     * @param string $response
     * @param array $extra_params array $extra_params an array of extra variables to post to the server
     *
     * @throws \Guzzle\Http\Exception\CurlException
     *
     * @throws \Symfony\Component\Validator\Exception\ValidatorException
     * @return Boolean
     */
    protected function checkAnswer($privateKey, $remoteip, $challenge, $response, $extra_params = array())
    {
        if ($remoteip == null || $remoteip == '') {
            throw new ValidatorException('For security reasons, you must pass the remote ip to reCAPTCHA');
        }

        // discard spam submissions
        if ($challenge == null || strlen($challenge) == 0 || $response == null || strlen($response) == 0) {
            return false;
        }
        $url = $this->getUrl();

        try {
            $response = $this->httpPost($url, '/recaptcha/api/verify', array(
                    'privatekey' => $privateKey,
                    'remoteip' => $remoteip,
                    'challenge' => $challenge,
                    'response' => $response
                ) + $extra_params, $this->getOptions());
        } catch (\Guzzle\Http\Exception\CurlException $e) {
            if ($e->getErrorNo() == CURLE_OPERATION_TIMEOUTED) {
                return true;
            }
            throw $e;
        }

        $body = $response->getBody(true);

        $answers = explode ("\n", $body);

        if (trim($answers[0]) == 'true') {
            return true;
        }

        return false;
    }

    /**
     * @return string
     */
    public function getUrl()
    {
        return $this->url;
    }

    /**
     * @param string $url
     *
     * @return null
     */
    public function setUrl($url)
    {
        return $url;
    }

    /**
     * @return Client
     */
    public function getClient() {
        return $this->client;
    }

    public function setClient($client) {
        if (!$client) {
            $client = new \Guzzle\Http\Client();
        }
        $this->client = $client;
        $this->client->setConfig(array(
            'curl.options' => array(
                'CURLOPT_NOSIGNAL'   => true
            ),
            'select_timeout' => 0.3
        ));
    }

    protected function httpPost($url, $path, $params, $options = array())
    {
        $client = $this->getClient();
        $client->setBaseUrl($url);

        $request = $client->post($path, null, $params, $options);
        $response = $request->send();
        return $response;
    }

    /**
     * @return array
     */
    public function getOptions()
    {
        return $this->options;
    }

    /**
     * @param array $options
     */
    public function setOptions($options)
    {
        $this->options = $options;
    }
}
