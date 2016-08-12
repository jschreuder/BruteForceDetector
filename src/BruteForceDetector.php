<?php declare(strict_types = 1);

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
            CREATE TABLE ' . $tableName . ' (
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
     * An array of types with their maximum of allowed misses, these are the defaults
     * and may be overwritten through the constructor
     *
     * @var  array
     */
    private $typeConfig = [
        self::TYPE_IP    => 1000,
        self::TYPE_USER  => 1000,
        self::TYPE_TOKEN => 1000,
    ];

    /**
     * Name of the SQL table holding the fail logs
     *
     * @var  string
     */
    private $tableName;

    public function __construct(\PDO $pdo, array $typeConfig = null, $tableName = 'brute_force_log')
    {
        $this->pdo = $pdo;
        if ($typeConfig) {
            $this->typeConfig = $typeConfig;
        }
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
            $conditions[] = '(value = :' . $valueKey . ' AND fail_count > ' . $this->typeConfig[$type] . ')';
        }
        return implode(' OR ', $conditions);
    }

    /**
     * Log failure for a type of value
     *
     * @param   string $type
     * @param   string $value
     * @return  void
     */
    public function updateFail($type, $value)
    {
        $query = $this->pdo->prepare('
            INSERT INTO `' . $this->tableName . '` (value, fail_count) VALUES (:value, 1)
            ON DUPLICATE KEY UPDATE fail_count = fail_count + 1
        ');
        $query->execute([
            'value' => $type . ':' . $value,
        ]);
    }

    /**
     * Should be run periodically to get rid of low number failures in the DB over a recent period
     *
     * @param   int $maxAge in seconds
     * @param   int $maxFails
     * @return  void
     */
    public function cleanUp($maxAge, $maxFails)
    {
        if (!is_int($maxAge) || $maxAge < 0) {
            throw new \InvalidArgumentException('$maxAge must be an integer and greater than zero.');
        }
        if (!is_int($maxFails) || $maxFails < 0) {
            throw new \InvalidArgumentException('$maxFails must be an integer and greater than zero.');
        }

        $query = $this->pdo->prepare('
            DELETE FROM `' . $this->tableName . '`
                  WHERE last_update < :min_age
                    AND fail_count < :max_fails
        ');
        $query->execute([
            'min_age' => (new \DateTimeImmutable('-' . $maxAge . ' seconds'))->format('Y-m-d H:i:s'),
            'max_fails' => $maxFails,
        ]);
    }
}
