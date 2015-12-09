<?php

namespace Neutron\ReCaptcha;

use Guzzle\Http\Client;
use Guzzle\Http\ClientInterface;
use Neutron\ReCaptcha\Exception\InvalidArgumentException;
use Symfony\Component\HttpFoundation\Request;

/** @see https://developers.google.com/recaptcha/docs/customization */
class ReCaptcha
{
    private $client;
    private $publicKey;
    private $privateKey;

    public function __construct(ClientInterface $client, $publicKey, $privateKey)
    {
        $this->client = $client;
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    public function isSetup()
    {
        return '' !== trim($this->privateKey) && '' !== trim($this->publicKey);
    }

    public function bind(Request $request, $challenge = 'recaptcha_challenge_field', $response = 'g-recaptcha-response')
    {
        return $this->checkAnswer($request->getClientIp(), $request->request->get($response));
    }

    public function checkAnswer($ip, $response)
    {
        if ('' === trim($ip)) {
            throw new InvalidArgumentException(
                'For security reasons, you must pass the remote ip to reCAPTCHA'
            );
        }

        if ( '' === trim($response)) {
            return new Response(false, 'incorrect-captcha-sol');
        }

        $request = $this->client->post('/recaptcha/api/siteverify');
        $request->addPostFields(array(
            'secret' => $this->privateKey,
            'remoteip'   => $ip,
            'response'   => $response
        ));

        $response = $request->send();
        $data = json_decode($response->getBody(true), true);

        if (true === $data['success']) {
            return new Response(true);
        }

        return new Response(false, isset($data['error-codes']) ? $data['error-codes'] : null);
    }

    public function getPublicKey()
    {
        return $this->publicKey;
    }

    public static function create($publicKey, $privateKey)
    {
        return new ReCaptcha(new Client('https://www.google.com/recaptcha/api/siteverify'), $publicKey, $privateKey);
    }
}
