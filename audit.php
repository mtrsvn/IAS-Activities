<?php
session_start();
if (!isset($_SESSION['user_id'])) {
  header('Location: password.php');
  exit;
}

$dbHost = 'localhost';
$dbName = 'password';
$dbUser = 'root';
$dbPass = '';

try {
    $pdo = new PDO(
        "mysql:host={$dbHost};dbname={$dbName};charset=utf8mb4",
        $dbUser,
        $dbPass,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]
    );
} catch (Throwable $e) {
    $dbConnectError = 'Unable to connect to the database: ' . $e->getMessage();
}

$rows = [];
if (!isset($dbConnectError)) {
  try {
    // Table: audit (Id, user, action, datetime)
    $stmt = $pdo->query('SELECT Id, user, action, datetime FROM audit ORDER BY datetime DESC');
    $rows = $stmt->fetchAll();
  } catch (Throwable $e) {
    $dbQueryError = 'Database query error: ' . $e->getMessage();
  }
}
?>
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Audit</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.5/dist/css/bootstrap.min.css">
  </head>
  <body class="bg-light">
    <div class="container py-5">
      <div class="row justify-content-center">
        <div class="col-12 col-xl-10">
          <div class="d-flex align-items-center mb-3">
            <h1 class="h4 mb-0">Audit Logs</h1>
            <div class="ms-auto d-flex gap-2">
              <a href="forms.php" class="btn btn-outline-secondary btn-sm">Back to Forms</a>
            </div>
          </div>

          <?php if (isset($dbConnectError)): ?>
            <div class="alert alert-danger" role="alert">
              <?php echo htmlspecialchars($dbConnectError); ?>
            </div>
          <?php elseif (isset($dbQueryError)): ?>
            <div class="alert alert-danger" role="alert">
              <?php echo htmlspecialchars($dbQueryError); ?>
            </div>
          <?php endif; ?>

          <div class="card shadow-sm">
            <div class="card-body">
              <div class="table-responsive">
                <table class="table table-striped align-middle">
                  <thead>
                    <tr>
                      <th scope="col">ID</th>
                      <th scope="col">User</th>
                      <th scope="col">Action</th>
                      <th scope="col">Datetime</th>
                    </tr>
                  </thead>
                  <tbody>
                    <?php if (!empty($rows)): ?>
                      <?php foreach ($rows as $row): ?>
                        <tr>
                          <td><?php echo htmlspecialchars((string)($row['Id'] ?? '')); ?></td>
                          <td><?php echo htmlspecialchars($row['user'] ?? ''); ?></td>
                          <td><?php echo htmlspecialchars($row['action'] ?? ''); ?></td>
                          <td><?php echo htmlspecialchars($row['datetime'] ?? '—'); ?></td>
                        </tr>
                      <?php endforeach; ?>
                    <?php else: ?>
                      <tr>
                        <td colspan="4" class="text-center text-muted">No audit entries found.</td>
                      </tr>
                    <?php endif; ?>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.5/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
