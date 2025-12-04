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
$confirm = '';
$formErrors = [];
$successMessage = '';

if ($method === 'POST' && !isset($dbConnectError)) {
		$username = isset($_POST['username']) ? trim((string)$_POST['username']) : '';
		$password = isset($_POST['password']) ? (string)$_POST['password'] : '';
		$confirm  = isset($_POST['confirm']) ? (string)$_POST['confirm'] : '';

		// Basic validation
		if ($username === '') {
				$formErrors['username'] = 'Username is required.';
		} elseif (!preg_match('/^[A-Za-z0-9_\.\-]{3,32}$/', $username)) {
				$formErrors['username'] = 'Use 3-32 letters, numbers, underscore, dot or dash.';
		}

		if ($password === '') {
			$formErrors['password'] = 'Password is required.';
		} else {
			$pwErrors = [];
			if (strlen($password) < 9) { // more than 8 characters
				$pwErrors[] = 'more than 8 characters';
			}
			if (!preg_match('/[A-Z]/', $password)) {
				$pwErrors[] = 'an uppercase letter';
			}
			if (!preg_match('/[0-9]/', $password)) {
				$pwErrors[] = 'a number';
			}
			if (!preg_match('/[@_!]/', $password)) {
				$pwErrors[] = 'a special character (@, _, !)';
			}
			if (!empty($pwErrors)) {
				$formErrors['password'] = 'Password must include ' . implode(', ', $pwErrors) . '.';
			}
		}

		if ($confirm === '' || $confirm !== $password) {
				$formErrors['confirm'] = 'Passwords do not match.';
		}

		if (empty($formErrors)) {
				try {
						// Check uniqueness
						$stmt = $pdo->prepare('SELECT id FROM users WHERE username = ? LIMIT 1');
						$stmt->execute([$username]);
						if ($stmt->fetch()) {
								$formErrors['username'] = 'Username is already taken.';
						} else {
								// Create user (store hashed password in `password` column)
								$passwordHash = password_hash($password, PASSWORD_DEFAULT);
								$stmt = $pdo->prepare('INSERT INTO users (username, password) VALUES (?, ?)');
								$stmt->execute([$username, $passwordHash]);

								// Auto-login and redirect to forms
								$userId = (int)$pdo->lastInsertId();
								$_SESSION['user_id'] = $userId;
								$_SESSION['username'] = $username;
								// audit registration success
								try {
									$auditStmt = $pdo->prepare('INSERT INTO audit (user, action, datetime) VALUES (:user, :action, NOW())');
									$auditStmt->execute([
										':user' => $username,
										':action' => 'User registered',
									]);
								} catch (Throwable $e) {
									// ignore audit failures
								}
								header('Location: forms.php');
								exit;
						}
				} catch (Throwable $e) {
						$formErrors['register'] = 'Registration failed.';
				}
		}
}
?>
<!doctype html>
<html lang="en">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>Create Account</title>
		<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.5/dist/css/bootstrap.min.css">
	</head>
	<body class="bg-light">
		<div class="container py-5">
			<div class="row justify-content-center">
				<div class="col-12 col-md-8 col-lg-6">
					<?php if (isset($dbConnectError)): ?>
						<div class="alert alert-danger" role="alert"><?php echo htmlspecialchars($dbConnectError); ?></div>
					<?php endif; ?>
					<?php if (isset($formErrors['register'])): ?>
						<div class="alert alert-danger" role="alert"><?php echo htmlspecialchars($formErrors['register']); ?></div>
					<?php endif; ?>

					<div class="card shadow-sm">
						<div class="card-header bg-white">
							<div class="d-flex justify-content-between align-items-center">
								<h1 class="h4 mb-0">Create Account</h1>
								<a href="password.php" class="btn btn-outline-secondary btn-sm">Back to Login</a>
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
										required
										minlength="3"
										maxlength="32"
										pattern="[A-Za-z0-9_\.\-]+"
									>
									<?php if (isset($formErrors['username'])): ?>
										<div class="invalid-feedback"><?php echo htmlspecialchars($formErrors['username']); ?></div>
									<?php endif; ?>
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
									>
									<?php if (isset($formErrors['password'])): ?>
										<div class="invalid-feedback"><?php echo htmlspecialchars($formErrors['password']); ?></div>
									<?php endif; ?>
								</div>

								<div class="mb-3">
									<label for="confirm" class="form-label">Confirm Password</label>
									<input
										type="password"
										class="form-control <?php echo isset($formErrors['confirm']) ? 'is-invalid' : ''; ?>"
										id="confirm"
										name="confirm"
										autocomplete="new-password"
										required
									>
									<?php if (isset($formErrors['confirm'])): ?>
										<div class="invalid-feedback"><?php echo htmlspecialchars($formErrors['confirm']); ?></div>
									<?php endif; ?>
								</div>

								<button id="submitBtn" type="submit" class="btn btn-primary w-100">Create Account</button>

								<ul class="list-unstyled small mt-3 mb-0" id="pwCriteria">
									<li class="criteria-item text-danger" data-rule="length">Password must be more than 8 characters</li>
									<li class="criteria-item text-danger" data-rule="uppercase">Password must have 1 uppercase letter</li>
									<li class="criteria-item text-danger" data-rule="special">Password must have special characters (@, _, !)</li>
									<li class="criteria-item text-danger" data-rule="number">Password must have numbers</li>
								</ul>
							</form>
						</div>
					</div>
				</div>
			</div>
		</div>

		<script>
			(function() {
				const usernameEl = document.getElementById('username');
				const passwordEl = document.getElementById('password');
				const confirmEl = document.getElementById('confirm');
				const submitBtn = document.getElementById('submitBtn');
				const criteriaList = document.getElementById('pwCriteria');

				function setRuleState(rule, ok) {
					const item = criteriaList.querySelector(`[data-rule="${rule}"]`);
					if (!item) return;
					item.classList.toggle('text-danger', !ok);
					item.classList.toggle('text-success', ok);
				}

				function updateValidity() {
					const uValid = usernameEl.checkValidity();
					const val = passwordEl.value || '';
					const rules = {
						length: val.length > 8,
						uppercase: /[A-Z]/.test(val),
						number: /[0-9]/.test(val),
						special: /[@_!]/.test(val),
					};

					Object.entries(rules).forEach(([rule, ok]) => setRuleState(rule, ok));

					const pValid = Object.values(rules).every(Boolean);
					const cValid = confirmEl.value === passwordEl.value && confirmEl.value.length > 0;
					submitBtn.disabled = !(uValid && pValid && cValid);
				}

				['input','blur','keyup','change'].forEach(evt => {
					usernameEl.addEventListener(evt, updateValidity);
					passwordEl.addEventListener(evt, updateValidity);
					confirmEl.addEventListener(evt, updateValidity);
				});

				updateValidity();
			})();
		</script>
	</body>
</html>
