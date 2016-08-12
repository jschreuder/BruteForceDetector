BruteForceDetector
==================

.. image:: https://scrutinizer-ci.com/g/WebspotCode/BruteForceDetector/badges/quality-score.png?b=master
   :target: https://scrutinizer-ci.com/g/WebspotCode/BruteForceDetector/?branch=master
   :alt: Scrutinizer Code Quality
.. image:: https://scrutinizer-ci.com/g/WebspotCode/BruteForceDetector/badges/coverage.png?b=master
   :target: https://scrutinizer-ci.com/g/WebspotCode/BruteForceDetector/?branch=master
   :alt: Code Coverage

This library keeps a log in your database that keeps track of login failures
for example. This should allow you to prevent someone from brute forcing a
password for example, and also provide some additional protection against
timing attacks.

Let's say for example you have the following code:

.. code:: php

  use Psr\Http\Message\ServerRequestInterface;
  class LoginController {
      private $authService;

      public function __construct(AuthService $authService)
      {
          $this->authService = $authService;
      }

      function login(ServerRequestInterface $request)
      {
          $requestParams = $request->getParsedBody();
          if (!$this->authService->login($requestParams['user'], $requestParams['pass'])) {
              return 'FAIL';
          }
          return 'SUCCESS';
      }
  }

This may be brute forced without impunity, so let's implement the BruteForceDetector:

.. code:: php

  use Psr\Http\Message\ServerRequestInterface;
  class LoginController {
      private $authService;
      private $bruteForceDetector;

      public function __construct(AuthService $authService, BruteForceDetector $bruteForceDetector)
      {
          $this->authService = $authService;
          $this->bruteForceDetector = $bruteForceDetector;
      }

      function login(ServerRequestInterface $request)
      {
          $requestParams = $request->getParsedBody();
          $requestIp = $request->getClientIp();

          // Block if already too many tries for either the given user or from current IP
          if ($this->bruteForceDetector->isBlocked($requestIp, $requestParams['user'])) {
              return 'BLOCKED';
          }

          if (!$this->authService->login($requestParams['user'], $requestParams['pass'])) {
              $this->bruteForceDetector->updateFail(BruteForceDetector::TYPE_IP, $requestIp);
              $this->bruteForceDetector->updateFail(BruteForceDetector::TYPE_USER, $requestParams['user']);
              return 'FAIL';
          }

          return 'SUCCESS';
      }
  }
