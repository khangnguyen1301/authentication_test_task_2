# Simple Test - Just Check Database Before/After
Write-Host "=== SIMPLE LOGOUT TEST ===" -ForegroundColor Cyan
Write-Host ""

# Get user info from database
Write-Host "Current refresh tokens:" -ForegroundColor Yellow
docker exec auth_system_mysql mysql -uauth_user -pauth_password auth_system -e "SELECT LEFT(id, 8) as id, LEFT(user_id, 8) as userId, is_revoked FROM refresh_tokens ORDER BY created_at DESC LIMIT 5;"
Write-Host ""

Write-Host "Current key pairs:" -ForegroundColor Yellow
docker exec auth_system_mysql mysql -uauth_user -pauth_password auth_system -e "SELECT LEFT(id, 8) as id, LEFT(userId, 8) as userId, isActive, revokedAt FROM key_pairs ORDER BY createdAt DESC LIMIT 5;"
Write-Host ""

Write-Host "Now please:" -ForegroundColor Green
Write-Host "1. Open Postman or browser" -ForegroundColor White
Write-Host "2. Login to get tokens" -ForegroundColor White
Write-Host "3. Call POST http://localhost:3000/api/auth/logout/secure" -ForegroundColor White
Write-Host "   Headers:" -ForegroundColor White
Write-Host "   - Authorization: Bearer <access_token>" -ForegroundColor Gray
Write-Host "   - x-client-id: <user_id>" -ForegroundColor Gray
Write-Host "   Body:" -ForegroundColor White
Write-Host "   { ""refreshToken"": ""<refresh_token>"" }" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Then run this script again to see changes" -ForegroundColor White
Write-Host ""

$response = Read-Host "Press Enter to check database again (or Ctrl+C to exit)"

Write-Host ""
Write-Host "Checking database after logout..." -ForegroundColor Yellow
Write-Host ""

Write-Host "Refresh tokens (should see is_revoked=1):" -ForegroundColor Yellow
docker exec auth_system_mysql mysql -uauth_user -pauth_password auth_system -e "SELECT LEFT(id, 8) as id, LEFT(user_id, 8) as userId, is_revoked FROM refresh_tokens ORDER BY created_at DESC LIMIT 5;"
Write-Host ""

Write-Host "Key pairs (should see isActive=0):" -ForegroundColor Yellow
docker exec auth_system_mysql mysql -uauth_user -pauth_password auth_system -e "SELECT LEFT(id, 8) as id, LEFT(userId, 8) as userId, isActive, revokedAt FROM key_pairs ORDER BY createdAt DESC LIMIT 5;"
