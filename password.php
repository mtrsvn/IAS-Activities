<?php
session_start();
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

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

$username = '';
$password = '';
$formErrors = [];
$successMessage = '';

if ($method === 'POST') {
		$username = isset($_POST['username']) ? trim((string)$_POST['username']) : '';
		$password = isset($_POST['password']) ? (string)$_POST['password'] : '';

		if ($username === '' || $password === '') {
			$formErrors['login'] = 'Username and password are required.';
		} else {
			try {
				$stmt = $pdo->prepare('SELECT id, username, password FROM users WHERE username = ? LIMIT 1');
				$stmt->execute([$username]);
				$userRow = $stmt->fetch();
				if ($userRow && password_verify($password, $userRow['password'])) {
					$_SESSION['user_id'] = $userRow['id'];
					$_SESSION['username'] = $userRow['username'];
					// audit login success
					try {
						$auditStmt = $pdo->prepare('INSERT INTO audit (user, action, datetime) VALUES (:user, :action, NOW())');
						$auditStmt->execute([
							':user' => $userRow['username'],
							':action' => 'User logged in',
						]);
					} catch (Throwable $e) {
						// ignore audit failures
					}
					header('Location: forms.php');
					exit;
				} else {
					$formErrors['login'] = 'Invalid username or password.';
				}
			} catch (Throwable $e) {
				$formErrors['login'] = 'Login failed.';
			}
		}
}
?>
<!doctype html>
<html lang="en">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>Login</title>
		<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.5/dist/css/bootstrap.min.css">
		<style>
			.criteria-item::before { content: ''; }
		</style>
	</head>
	<body class="bg-light">
		<div class="container py-5">
			<div class="row justify-content-center">
				<div class="col-12 col-md-8 col-lg-6">
					<?php if (isset($dbConnectError)): ?>
						<div class="alert alert-danger" role="alert"><?php echo htmlspecialchars($dbConnectError); ?></div>
					<?php endif; ?>
					<?php if (isset($formErrors['login'])): ?>
						<div class="alert alert-danger" role="alert"><?php echo htmlspecialchars($formErrors['login']); ?></div>
					<?php endif; ?>

					<div class="card shadow-sm">
						<div class="card-header bg-white">
							<div class="d-flex justify-content-between align-items-center">
								<h1 class="h4 mb-0">Login</h1>
								<a href="register.php" class="btn btn-outline-secondary btn-sm">Create Account</a>
							</div>
						</div>
						<div class="card-body">
							<form method="post" novalidate>
								<div class="mb-3">
									<label for="username" class="form-label">Username</label>
									<input
										type="text"
										class="form-control <?php echo isset($formErrors['username']) ? 'is-invalid' : ''; ?>"
										id="username"
										name="username"
										value="<?php echo htmlspecialchars($username); ?>"
										placeholder=""
										required
									>
                                    
								</div>

								<div class="mb-3">
									<label for="password" class="form-label">Password</label>
									<input
										type="password"
										class="form-control <?php echo isset($formErrors['password']) ? 'is-invalid' : ''; ?>"
										id="password"
										name="password"
										autocomplete="new-password"
										required
										aria-describedby="passwordHelp"
									>
							
								</div>

								<button id="submitBtn" type="submit" class="btn btn-primary w-100">Login</button>
							</form>
						</div>
					</div>
				</div>
			</div>
		</div>

		<script>
			(function() {
				const passwordEl = document.getElementById('password');
				const usernameEl = document.getElementById('username');
				const submitBtn = document.getElementById('submitBtn');

				function updateValidity() {
					const usernameValid = usernameEl.checkValidity();
					const pwFilled = (passwordEl.value || '').length > 0;
					submitBtn.disabled = !(usernameValid && pwFilled);
				}

				['input', 'blur', 'keyup', 'change'].forEach(evt => {
					passwordEl.addEventListener(evt, updateValidity);
					usernameEl.addEventListener(evt, updateValidity);
				});

				updateValidity();
			})();
		</script>
	</body>
</html>

