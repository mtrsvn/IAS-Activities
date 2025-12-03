<?php
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

$username = '';
$password = '';
$formErrors = [];
$passwordChecks = [
		'length' => false,
		'uppercase' => false,
		'special' => false,
		'digit' => false,
];

if ($method === 'POST') {
		$username = isset($_POST['username']) ? trim((string)$_POST['username']) : '';
		$password = isset($_POST['password']) ? (string)$_POST['password'] : '';
                

		$passwordChecks['length'] = strlen($password) > 8;
		$passwordChecks['uppercase'] = (bool)preg_match('/[A-Z]/', $password);
		$passwordChecks['special'] = (bool)preg_match('/[@_!]/', $password);
		$passwordChecks['digit'] = (bool)preg_match('/\d/', $password);

		$allPassRules = $passwordChecks['length'] && $passwordChecks['uppercase'] && $passwordChecks['special'] && $passwordChecks['digit'];

		if (!$allPassRules) {
				$formErrors['password'] = 'Password does not meet the required criteria.';
		}

		if (empty($formErrors)) {
			$successMessage = 'Logged in successfully (demo).';
			$username = '';
				$password = '';
				$passwordChecks = [
						'length' => false,
						'uppercase' => false,
						'special' => false,
						'digit' => false,
				];
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
					<?php if (!empty($successMessage)): ?>
						<div class="alert alert-success" role="alert">
							<?php echo htmlspecialchars($successMessage); ?>
						</div>
					<?php endif; ?>

					<div class="card shadow-sm">
						<div class="card-header bg-white">
							<h1 class="h4 mb-0">Login</h1>
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

								<ul class="list-unstyled small mb-3" aria-live="polite">
									<li id="crit-length" class="criteria-item <?php echo $passwordChecks['length'] ? 'text-success' : 'text-danger'; ?>" aria-label="More than 8 characters"></li>
									<li id="crit-uppercase" class="criteria-item <?php echo $passwordChecks['uppercase'] ? 'text-success' : 'text-danger'; ?>" aria-label="At least 1 uppercase letter"></li>
									<li id="crit-special" class="criteria-item <?php echo $passwordChecks['special'] ? 'text-success' : 'text-danger'; ?>" aria-label="At least 1 special character (@, _, !)"></li>
									<li id="crit-digit" class="criteria-item <?php echo $passwordChecks['digit'] ? 'text-success' : 'text-danger'; ?>" aria-label="At least 1 number"></li>
								</ul>

                                

								<button id="submitBtn" type="submit" class="btn btn-primary w-100" disabled>Login</button>
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

				const critEls = {
					length: document.getElementById('crit-length'),
					uppercase: document.getElementById('crit-uppercase'),
					special: document.getElementById('crit-special'),
					digit: document.getElementById('crit-digit'),
				};

				function checkPassword(pw) {
					return {
						length: pw.length > 8,
						uppercase: /[A-Z]/.test(pw),
						special: /[@_!]/.test(pw),
						digit: /\d/.test(pw),
					};
				}

				function updateCriteriaUI(checks) {
					Object.keys(critEls).forEach(key => {
						const el = critEls[key];
						el.classList.toggle('text-success', !!checks[key]);
						el.classList.toggle('text-danger', !checks[key]);
					});
				}

				function updateValidity() {
					const pw = passwordEl.value || '';
					const checks = checkPassword(pw);
					updateCriteriaUI(checks);
					const allPass = checks.length && checks.uppercase && checks.special && checks.digit;

					if (pw.length > 0) {
						passwordEl.classList.toggle('is-valid', allPass);
						passwordEl.classList.toggle('is-invalid', !allPass);
					} else {
						passwordEl.classList.remove('is-valid', 'is-invalid');
					}

					const usernameValid = usernameEl.checkValidity();
                
					const formOk = usernameValid && allPass;
					submitBtn.disabled = !formOk;
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

