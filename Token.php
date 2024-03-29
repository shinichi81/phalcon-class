<?php

namespace App;

class Token extends Component
{

    public function getToken($tokenKey, $lifetime = 0, $numberBytes = null)
    {
        if (null === $numberBytes) {
            $numberBytes = 12;
        }

        if (0 !== $lifetime) {
            $lifetime = \time() + $lifetime;
        }

        if (false === function_exists('openssl_random_pseudo_bytes')) {
            throw new \Exception('Openssl extension must be loaded');
        }
        $token = \md5(openssl_random_pseudo_bytes($numberBytes));

        $this->session->set('$Token-' . $tokenKey, $token);
        $this->session->set('$TokenTime-' . $tokenKey, $lifetime);

        return $token;
    }

    public function checkToken($tokenKey, $tokenValue)
    {
        $token = $this->getSessionToken($tokenKey);
        if (null !== $token) {
            if ($tokenValue === $token) {
                return true;
            }
        }
        return false;
    }

    public function getSessionToken($tokenKey)
    {
        if ($this->session->has('$Token-' . $tokenKey)) {
            $token = $this->session->get('$Token-' . $tokenKey, null);
            $lifetime = (int)$this->session->get('$TokenTime-' . $tokenKey, 0);
            if (0 === $lifetime) {
                return $token;
            }

            $time = \time();
            if ($time < $lifetime) {
                return $token;
            }else {
                $this->session->remove('$Token-' . $tokenKey);
                $this->session->remove('$TokenTime-' . $tokenKey);
            }
        }
        return null;
    }
}
