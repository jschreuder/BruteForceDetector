BruteForceDetector
==================

.. image:: https://scrutinizer-ci.com/g/WebspotCode/BruteForceDetector/badges/build.png?b=master
   :target: https://scrutinizer-ci.com/g/WebspotCode/BruteForceDetector/?branch=master
   :alt: Build status
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
          $checks = [
              BruteForceDetector::TYPE_IP => $request->getClientIp(),
              BruteForceDetector::TYPE_USER => $requestParams['user'],
          ];

          // Block if already too many tries for either the given user or from current IP
          if ($this->bruteForceDetector->isBlocked($checks)) {
              return 'BLOCKED';
          }

          if (!$this->authService->login($requestParams['user'], $requestParams['pass'])) {
              $this->bruteForceDetector->updateFails($checks);
              return 'FAIL';
          }

          return 'SUCCESS';
      }
  }

The library itself does not automatically expire failure logs or unblock. So
you probably need to implement this yourself. The library does provide two
methods to assist with this:

``expireLowFailures($maxAge = 86400, $maxFailPercentage = 2.5)``

This method will check all logs updated within the timespan given in
``$maxAge`` and delete them if their number of failures is below the given
``$maxFailPercentage`` of the number of failures that will cause the value to
be blocked. The defaults are to check for updates within the last day (86400
seconds) and with failure rate of 25 or lower (2.5% of 1000).

It is recommended to put this in a CRON-job to run daily.

``unBlock($type, $value)``

Once a value is blocked it will not unblock automatically. You can use this
method to unblock a given value and type by removing their log.

``getBlockedValues($maxAge = 2419200)``

Will return a list of all type/value combinations blocked within the given
period. This defaults to the last 4 weeks.
