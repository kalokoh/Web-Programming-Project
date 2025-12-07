<?php
require_once 'config.php';
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    //$role = in_array($_POST['role'] ?? 'user', ['admin','agent','manager','player']) ? $_POST['role'] : 'user';
    $role_raw = strtolower($_POST['role'] ?? 'user'); 
    $allowed_roles = ['admin','agent','manager','player', 'user'];
    $role = in_array($role_raw, $allowed_roles) ? $role_raw : 'user';

    if (!$name) $errors[] = 'Name required';
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Valid email required';
    if (strlen($password) < 6) $errors[] = 'Password must be at least 6 characters';

    if (empty($errors)) {
        // check if email exists
        $stmt = $mysqli->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param('s', $email);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $errors[] = 'Email already registered';
        } else {
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $ins = $mysqli->prepare("INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)");
            $ins->bind_param('ssss', $name, $email, $hash, $role);
            if ($ins->execute()) {
                header('Location: login.php?registered=1');
                exit;
            } else {
                $errors[] = 'Database error: ' . $mysqli->error;
            }
        }
    }
}
include 'header.php';
?>
<h2>Register</h2>
<?php if ($errors): ?>
  <div class="alert alert-danger">
    <?php foreach($errors as $err) echo '<div>'.e($err).'</div>'; ?>
  </div>
<?php endif; ?>
<form method="post" class="mb-4">
  <div class="mb-3"><label class="form-label">Name</label><input class="form-control" name="name" required></div>
  <div class="mb-3"><label class="form-label">Email</label><input class="form-control" type="email" name="email" required></div>
  <div class="mb-3"><label class="form-label">Password</label><input class="form-control" type="password" name="password" required></div>
  <div class="mb-3"><label class="form-label">Role</label>
    <select name="role" class="form-select">
      <option value="user">User</option>
      <option value="admin">Admin</option>
      <option value="agent">Agent</option>
      <option value="manager">Manager</option>
      <option value="player">Player</option>
    </select>
  </div>
  <button class="btn btn-primary">Register</button>
</form>
<?php include 'footer.php'; ?>
