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

$now = time();
if (!isset($dbConnectError) && isset($_GET['mfa']) && $_GET['mfa'] === '1') {
  
  $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
  $_SESSION['mfa_code'] = $code;
  $_SESSION['mfa_expires'] = $now + 300;
  header('Content-Type: application/json');
  echo json_encode(['code' => $code, 'expiresIn' => 300]);
  exit;
}

function validate_mfa(): array {
  $code = isset($_POST['mfa_code']) ? trim((string)$_POST['mfa_code']) : '';
  $sessionCode = $_SESSION['mfa_code'] ?? null;
  $expires = $_SESSION['mfa_expires'] ?? 0;
  $now = time();
  if ($sessionCode === null || $expires < $now) {
    return [false, 'MFA code expired. Please request a new code.'];
  }
  if ($code === '' || !preg_match('/^\d{6}$/', $code)) {
    return [false, 'Enter a valid 6-digit MFA code.'];
  }
  if (hash_equals((string)$sessionCode, $code)) {
    unset($_SESSION['mfa_code'], $_SESSION['mfa_expires']);
    return [true, ''];
  }
  return [false, 'Invalid MFA code.'];
}

$rows = [];
if (!isset($dbConnectError)) {
  
  if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    [$mfaOk, $mfaMsg] = validate_mfa();
    if (!$mfaOk) {
      $flashError = $mfaMsg;
    } else {
      $id = isset($_POST['delete_id']) ? (int)$_POST['delete_id'] : 0;
      if ($id > 0) {
        try {
          $stmt = $pdo->prepare('DELETE FROM forms WHERE id = :id');
          $stmt->execute([':id' => $id]);
          try {
            $auditStmt = $pdo->prepare('INSERT INTO audit (user, action, datetime) VALUES (:user, :action, NOW())');
            $auditStmt->execute([
              ':user' => $_SESSION['username'] ?? 'unknown',
              ':action' => 'Deleted form record ID ' . $id,
            ]);
          } catch (Throwable $e) {
            
          }
          $flashSuccess = 'Record deleted successfully.';
        } catch (Throwable $e) {
          $flashError = 'Failed to delete record: ' . $e->getMessage();
        }
      } else {
        $flashError = 'Invalid record id for delete.';
      }
    }
  }

  
  if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_id'])) {
    [$mfaOk, $mfaMsg] = validate_mfa();
    if (!$mfaOk) {
      $flashError = $mfaMsg;
    } else {
      $editId = (int)($_POST['edit_id'] ?? 0);
      $editUsername = trim((string)($_POST['edit_username'] ?? ''));
      if ($editId > 0 && $editUsername !== '') {
        try {
          $stmt = $pdo->prepare('UPDATE forms SET username = :username WHERE id = :id');
          $stmt->execute([':username' => $editUsername, ':id' => $editId]);
          try {
            $auditStmt = $pdo->prepare('INSERT INTO audit (user, action, datetime) VALUES (:user, :action, NOW())');
            $auditStmt->execute([
              ':user' => $_SESSION['username'] ?? 'unknown',
              ':action' => 'Edited form record ID ' . $editId . ' set username to ' . $editUsername,
            ]);
          } catch (Throwable $e) {
            
          }
          $flashSuccess = 'Username updated successfully.';
        } catch (Throwable $e) {
          $flashError = 'Failed to update username: ' . $e->getMessage();
        }
      } else {
        $flashError = 'Invalid edit data.';
      }
    }
  }

  
  if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['new_username'])) {
    $newUsername = trim((string)($_POST['new_username'] ?? ''));
    if ($newUsername !== '') {
      try {
        
        $stmt = $pdo->prepare('INSERT INTO forms (username, datetime) VALUES (:username, NOW())');
        $stmt->execute([':username' => $newUsername]);
        try {
          $auditStmt = $pdo->prepare('INSERT INTO audit (user, action, datetime) VALUES (:user, :action, NOW())');
          $auditStmt->execute([
            ':user' => $_SESSION['username'] ?? 'unknown',
            ':action' => 'Added form record for username ' . $newUsername,
          ]);
        } catch (Throwable $e) {
          
        }
        $flashSuccess = 'Username added successfully.';
      } catch (Throwable $e) {
        $flashError = 'Failed to add username: ' . $e->getMessage();
      }
    } else {
      $flashError = 'Username cannot be empty.';
    }
  }
    try {
    // Read from forms table with expected columns
    $stmt = $pdo->query('SELECT id, username, datetime FROM forms ORDER BY datetime DESC');
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
    <title>Forms</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.5/dist/css/bootstrap.min.css">
  </head>
  <body class="bg-light">
    <div class="container py-5">
      <div class="row justify-content-center">
        <div class="col-12 col-xl-10">
          <div class="d-flex align-items-center mb-3">
            <h1 class="h4 mb-0">User Forms</h1>
            <div class="ms-auto d-flex gap-2">
              <a href="audit.php" class="btn btn-primary btn-sm">Audit</a>
              <a href="password.php" class="btn btn-outline-secondary btn-sm">Back to Login</a>
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
          <?php elseif (isset($flashSuccess)): ?>
            <div class="alert alert-success" role="alert">
              <?php echo htmlspecialchars($flashSuccess); ?>
            </div>
          <?php elseif (isset($flashError)): ?>
            <div class="alert alert-danger" role="alert">
              <?php echo htmlspecialchars($flashError); ?>
            </div>
          <?php endif; ?>

          
          <div class="modal fade" id="editModal" tabindex="-1" aria-labelledby="editModalLabel" aria-hidden="true">
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="editModalLabel">Edit Username</h5>
                  <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form method="post">
                  <div class="modal-body">
                    <input type="hidden" name="edit_id" id="edit_id">
                    <div class="mb-3">
                      <label for="edit_username" class="form-label">Username</label>
                      <input type="text" class="form-control" id="edit_username" name="edit_username" required>
                    </div>
                    <input type="hidden" id="edit_mfa_code" name="mfa_code">
                  </div>
                  <div class="modal-footer">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Save changes</button>
                  </div>
                </form>
              </div>
            </div>
          </div>

          
          <div class="modal fade" id="deleteModal" tabindex="-1" aria-labelledby="deleteModalLabel" aria-hidden="true">
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="deleteModalLabel">Confirm Delete</h5>
                  <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form method="post">
                  <div class="modal-body">
                    <p class="mb-2">Are you sure you want to delete this record?</p>
                    <input type="hidden" name="delete_id" id="delete_id">
                    <input type="hidden" id="delete_mfa_code" name="mfa_code">
                  </div>
                  <div class="modal-footer">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-danger">Delete</button>
                  </div>
                </form>
              </div>
            </div>
          </div>

          
          <div class="modal fade" id="mfaModal" tabindex="-1" aria-labelledby="mfaModalLabel" aria-hidden="true">
            <div class="modal-dialog">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title" id="mfaModalLabel">Multi‑Factor Verification</h5>
                  <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                  <p class="mb-2">Please verify with a one‑time 6‑digit code.</p>
                  <div class="d-flex align-items-center">
                    <div class="me-2" style="min-width:200px;">
                      <label class="form-label mb-0" for="mfa_code_input">MFA Code</label>
                      <input type="text" class="form-control" id="mfa_code_input" inputmode="numeric" pattern="\d{6}" maxlength="6" placeholder="Enter 6-digit code" required>
                    </div>
                    <button type="button" class="btn btn-outline-secondary ms-2" id="btnGetGlobalOtp">Get OTP</button>
                  </div>
                  <div class="form-text" id="mfaOtpInfo"></div>
                </div>
                <div class="modal-footer">
                  <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                  <button type="button" class="btn btn-primary" id="btnMfaContinue">Continue</button>
                </div>
              </div>
            </div>
          </div>

          <div class="card shadow-sm mb-3">
            <div class="card-body">
              <form method="post" class="row g-2 align-items-center">
                <div class="col-sm-8 col-md-9">
                  <label for="new_username" class="form-label mb-0">Username</label>
                  <input type="text" class="form-control" id="new_username" name="new_username" placeholder="Enter username" required>
                </div>
                <div class="col-sm-4 col-md-3 d-grid">
                  <label class="form-label mb-0" style="visibility:hidden">Add</label>
                  <button type="submit" class="btn btn-primary">Add</button>
                </div>
              </form>
            </div>
          </div>

          <div class="card shadow-sm">
            <div class="card-body">
              <div class="table-responsive">
                <table class="table table-striped align-middle">
                  <thead>
                    <tr>
                      <th scope="col">ID</th>
                      <th scope="col">Username</th>
                      <th scope="col">Datetime</th>
                      <th scope="col" class="text-end">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    <?php if (!empty($rows)): ?>
                      <?php foreach ($rows as $row): ?>
                        <tr>
                          <td><?php echo htmlspecialchars((string)($row['id'] ?? '')); ?></td>
                          <td><?php echo htmlspecialchars($row['username'] ?? ''); ?></td>
                          <td><?php echo htmlspecialchars($row['datetime'] ?? '—'); ?></td>
                          <td class="text-end">
                            <div class="btn-group btn-group-sm" role="group" aria-label="Actions">
                              <?php
                                $id = (int)($row['id'] ?? 0);
                                $idParam = urlencode((string)$id);
                              ?>
                              <button
                                type="button"
                                class="btn btn-outline-primary"
                                data-action="edit"
                                data-id="<?php echo $idParam; ?>"
                                data-username="<?php echo htmlspecialchars($row['username'] ?? '', ENT_QUOTES); ?>"
                                data-bs-toggle="modal"
                                data-bs-target="#mfaModal"
                              >Edit</button>
                              <button
                                type="button"
                                class="btn btn-outline-danger"
                                data-action="delete"
                                data-id="<?php echo $idParam; ?>"
                                data-bs-toggle="modal"
                                data-bs-target="#mfaModal"
                              >Delete</button>
                            </div>
                          </td>
                        </tr>
                      <?php endforeach; ?>
                    <?php else: ?>
                      <tr>
                        <td colspan="4" class="text-center text-muted">No forms found.</td>
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
  <script>
    
    const editModal = document.getElementById('editModal');
    if (editModal) {
      editModal.addEventListener('show.bs.modal', (event) => {
        const button = event.relatedTarget;
        
        const id = (button && button.getAttribute('data-id')) || (window._pendingEdit && window._pendingEdit.id) || '';
        const username = (button && button.getAttribute('data-username')) || (window._pendingEdit && window._pendingEdit.username) || '';

        const idInput = document.getElementById('edit_id');
        const usernameInput = document.getElementById('edit_username');
        if (idInput) idInput.value = id || '';
        if (usernameInput) usernameInput.value = username || '';
        const editMfaInput = document.getElementById('edit_mfa_code');
        if (editMfaInput && window._mfaCode) editMfaInput.value = window._mfaCode;
      });
    }

    
    const deleteModal = document.getElementById('deleteModal');
    if (deleteModal) {
      deleteModal.addEventListener('show.bs.modal', (event) => {
        const button = event.relatedTarget;
        const id = (button && button.getAttribute('data-id')) || (window._pendingDelete && window._pendingDelete.id) || '';
        const idInput = document.getElementById('delete_id');
        if (idInput) idInput.value = id || '';
        const deleteMfaInput = document.getElementById('delete_mfa_code');
        if (deleteMfaInput && window._mfaCode) deleteMfaInput.value = window._mfaCode;
      });
    }

    async function requestOtp(infoElemId) {
      try {
        const res = await fetch('forms.php?mfa=1', { headers: { 'Accept': 'application/json' } });
        if (!res.ok) throw new Error('Failed to get OTP');
        const data = await res.json();
        const el = document.getElementById(infoElemId);
        if (el) {
          el.textContent = `Your OTP is ${data.code}. It expires in ${Math.floor((data.expiresIn || 300) / 60)} minutes.`;
        }
        window._mfaCode = data.code;
      } catch (e) {
        const el = document.getElementById(infoElemId);
        if (el) el.textContent = 'Unable to fetch OTP. Please try again.';
      }
    }

    
    const mfaModal = document.getElementById('mfaModal');
    const btnGetGlobalOtp = document.getElementById('btnGetGlobalOtp');
    const mfaOtpInfo = document.getElementById('mfaOtpInfo');
    const mfaInput = document.getElementById('mfa_code_input');
    const btnMfaContinue = document.getElementById('btnMfaContinue');

    let nextAction = null;

    if (mfaModal) {
      mfaModal.addEventListener('show.bs.modal', (event) => {
        const button = event.relatedTarget;
        const actionType = button ? button.getAttribute('data-action') : null;
        if (actionType === 'edit') {
          nextAction = { type: 'edit', payload: { id: button.getAttribute('data-id'), username: button.getAttribute('data-username') } };
        } else if (actionType === 'delete') {
          nextAction = { type: 'delete', payload: { id: button.getAttribute('data-id') } };
        } else {
          nextAction = null;
        }
        if (mfaOtpInfo) mfaOtpInfo.textContent = '';
        if (mfaInput) { mfaInput.value = ''; mfaInput.focus(); }
        window._mfaCode = null;
      });
    }

    if (btnGetGlobalOtp) {
      btnGetGlobalOtp.addEventListener('click', () => requestOtp('mfaOtpInfo'));
    }

    if (btnMfaContinue) {
      btnMfaContinue.addEventListener('click', () => {
        const code = (mfaInput && mfaInput.value || '').trim();
        if (!/^\d{6}$/.test(code)) {
          if (mfaOtpInfo) mfaOtpInfo.textContent = 'Enter a valid 6-digit code.';
          return;
        }
        
        window._mfaCode = code;
        const bsModal = bootstrap.Modal.getInstance(mfaModal);
        if (bsModal) bsModal.hide();
        setTimeout(() => {
          if (!nextAction) return;
          if (nextAction.type === 'edit') {
            window._pendingEdit = { id: nextAction.payload.id, username: nextAction.payload.username };
            const em = new bootstrap.Modal(document.getElementById('editModal'));
            em.show();
          } else if (nextAction.type === 'delete') {
            window._pendingDelete = { id: nextAction.payload.id };
            const dm = new bootstrap.Modal(document.getElementById('deleteModal'));
            dm.show();
          }
        }, 150);
      });
    }
  </script>
</html>
