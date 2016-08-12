<?php

namespace Spot\BruteForceDetector;

class BruteForceDetector
{
    /**
     * Creating the SQL table, this can be used in a migration for example
     *
     * @param   string $tableName
     * @return  string
     */
    public static function getCreateTableSQL($tableName = 'brute_force_log')
    {
        return '
            CREATE TABLE `' . $tableName . '` (
                value VARCHAR(160) NOT NULL,
                fail_count INT(11) NOT NULL,
                last_update TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY (value)
            ) ENGINE = InnoDB
        ';
    }

    /**
     * Predefined type constants
     */
    const TYPE_IP = 'ip';
    const TYPE_USER = 'user';
    const TYPE_TOKEN = 'token';

    /** @var  \PDO */
    private $pdo;

    /**
     * Maximum number of failures allowed on a type of value
     *
     * @var  int
     */
    private $maxFailures = 1000;

    /**
     * Name of the SQL table holding the fail logs
     *
     * @var  string
     */
    private $tableName;

    public function __construct(\PDO $pdo, $maxFailures = 1000, $tableName = 'brute_force_log')
    {
        $this->pdo = $pdo;
        $this->maxFailures = intval($maxFailures);
        $this->tableName = $tableName;
    }

    /**
     * An array of checks to perform, for example:
     *
     *     [
     *         BruteForceDetector::TYPE_IP => '127.0.0.1',
     *         BruteForceDetector::TYPE_USER => 'me@localhost',
     *     ]
     *
     * @param   array $checks
     * @return  bool
     */
    public function isBlocked(array $checks)
    {
        $values = [];
        $query = $this->pdo->prepare('
            SELECT value
              FROM `' . $this->tableName . '`
             WHERE ' . $this->buildWhere($checks, $values)
        );
        $query->execute($values);

        return $query->rowCount() > 0;
    }

    /**
     * Builds the WHERE conditions for the isBlocked() method
     *
     * @param   array $checks
     * @param   array $values
     * @return  string
     */
    private function buildWhere(array $checks, array &$values)
    {
        $conditions = [];
        foreach ($checks as $type => $value) {
            $valueKey = 'val_' . uniqid();
            $values[$valueKey] = $value;
            $conditions[] = '(value = :' . $valueKey . ' AND fail_count > ' . strval($this->maxFailures) . ')';
        }
        return implode(' OR ', $conditions);
    }

    /**
     * An array to log of types & values that failed
     *
     *     [
     *         BruteForceDetector::TYPE_IP => '127.0.0.1',
     *         BruteForceDetector::TYPE_USER => 'me@localhost',
     *     ]
     *
     * @param   array $checks
     * @return  void
     */
    public function updateFails(array $checks)
    {
        foreach ($checks as $type => $value) {
            $query = $this->pdo->prepare('
                INSERT INTO `' . $this->tableName . '` (value, fail_count) VALUES (:value, 1)
                ON DUPLICATE KEY UPDATE fail_count = fail_count + 1
            ');
            $query->execute([
                'value' => $type . ':' . $value,
            ]);
        }
    }

    /**
     * Should be run periodically to get rid of low number failures in the DB over a recent period
     *
     * @param   int $maxAge in seconds, defaults to 1 day)
     * @param   float $maxFailPercentage defaults to 2.5%
     * @return  void
     */
    public function expireLowFailures($maxAge = 86400, $maxFailPercentage = 2.5)
    {
        if (!is_int($maxAge) || $maxAge < 0) {
            throw new \InvalidArgumentException('$maxAge must be an integer and greater than zero.');
        }
        if (!is_int($maxFailPercentage) || $maxFailPercentage < 0 || $maxFailPercentage > 100) {
            throw new \InvalidArgumentException('$maxFailPercentage must be an integer and between 0 and 100.');
        }

        $query = $this->pdo->prepare('
            DELETE FROM `' . $this->tableName . '`
                  WHERE last_update > :max_age
                    AND fail_count < :max_fails
        ');
        $query->execute([
            'max_age' => (new \DateTimeImmutable('-' . $maxAge . ' seconds'))->format('Y-m-d H:i:s'),
            'max_fails' => ceil($this->maxFailures * ($maxFailPercentage / 100)),
        ]);
    }

    /**
     * Clear failure log for specific type/value combination
     *
     * @param   string $type
     * @param   string $value
     * @return  void
     */
    public function unBlock($type, $value)
    {
        $query = $this->pdo->prepare('
            DELETE FROM `' . $this->tableName . '`
                  WHERE value = :value
        ');
        $query->execute(['value' => $type . ':' . $value]);
    }

    /**
     * Returns all values blocked within the given timespan (defaults to 4 weeks)
     *
     * @param   int $maxAge
     * @return  array
     */
    public function getBlockedValues($maxAge = 2419200)
    {
        $query = $this->pdo->prepare('
              SELECT value, fail_count, last_update
                FROM `' . $this->tableName . '`
               WHERE fail_count > ' . strval($this->maxFailures) . '
                 AND last_update > :max_age
            ORDER BY last_update DESC
        ');
        $query->execute([
            'max_age' => (new \DateTimeImmutable('-' . $maxAge . ' seconds'))->format('Y-m-d H:i:s'),
        ]);

        $output = [];
        while ($row = $query->fetch(\PDO::FETCH_ASSOC)) {
            list($type, $value) = explode(':', $row['value'], 2);
            $output[] = [
                'type' => $type,
                'value' => $value,
                'last_update' => $row['last_update'],
            ];
        }
        return $output;
    }
}
