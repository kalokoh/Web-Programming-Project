<?php
require_once 'config.php';
$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'Valid email required';

    if (empty($errors)) {
        $stmt = $mysqli->prepare("SELECT id,name,password,role FROM users WHERE email = ?");
        $stmt->bind_param('s', $email);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows === 1) {
            $stmt->bind_result($id,$name,$hash,$role);
            $stmt->fetch();
            if (password_verify($password, $hash)) {
                // successful login
                $_SESSION['user_id'] = $id;
                $_SESSION['name'] = $name;
                $_SESSION['role'] = $role;
                header('Location: dashboard.php');
                exit;
            } else {
                $errors[] = 'Invalid credentials';
            }
        } else {
            $errors[] = 'No account with that email';
        }
    }
}
include 'header.php';
?>
<h2>Login</h2>
<?php if (!empty($_GET['registered'])): ?>
  <div class="alert alert-success">Registration successful. Please login.</div>
<?php endif; ?>
<?php if ($errors): ?>
  <div class="alert alert-danger"><?php foreach($errors as $err) echo '<div>'.e($err).'</div>'; ?></div>
<?php endif; ?>
<form method="post">
  <div class="mb-3"><label>Email</label><input class="form-control" name="email" type="email" required></div>
  <div class="mb-3"><label>Password</label><input class="form-control" name="password" type="password" required></div>
  <button class="btn btn-primary">Login</button>
</form>
<?php include 'footer.php'; ?>
