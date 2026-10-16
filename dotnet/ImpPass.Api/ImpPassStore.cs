using Google.Cloud.Firestore;
using BCrypt.Net;

namespace ImpPass.Api;

public sealed class ImpPassStore(FirestoreDb db)
{
    private readonly CollectionReference _users = db.Collection("users");
    private readonly CollectionReference _sessions = db.Collection("sessions");
    private readonly CollectionReference _data = db.Collection("data");

    public async Task RegisterAsync(string email, string password)
    {
        var userId = PasswordCrypto.StableId(email);
        var userRef = _users.Document(userId);
        var existing = await userRef.GetSnapshotAsync();
        if (existing.Exists)
            throw new ApiException(400, "User exists");

        var salt = PasswordCrypto.NewSalt();
        await userRef.SetAsync(new Dictionary<string, object>
        {
            ["email"] = email,
            ["passwordHash"] = BCrypt.HashPassword(password, 10),
            ["keySalt"] = PasswordCrypto.Base64UrlEncode(salt)
        });
    }

    public async Task<SessionContext> AuthenticateAsync(string email, string password)
    {
        var userId = PasswordCrypto.StableId(email);
        var user = await _users.Document(userId).GetSnapshotAsync();
        if (!user.Exists)
            throw new ApiException(400, "User not found");

        var passwordHash = user.GetValue<string>("passwordHash");
        if (!BCrypt.Verify(password, passwordHash))
            throw new ApiException(400, "Wrong Password");

        var salt = PasswordCrypto.Base64UrlDecode(user.GetValue<string>("keySalt"));
        var key = PasswordCrypto.DeriveKey(password, salt);
        return await CreateSessionAsync(userId, key);
    }

    public async Task<SessionContext?> GetSessionAsync(string sessionId)
    {
        var snapshot = await _sessions.Document(sessionId).GetSnapshotAsync();
        if (!snapshot.Exists)
            return null;

        var expireOn = snapshot.GetValue<long>("expireOn");
        if (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() > expireOn)
        {
            await _sessions.Document(sessionId).DeleteAsync();
            return null;
        }

        var key = PasswordCrypto.Base64UrlDecode(snapshot.GetValue<string>("key"));
        var userId = snapshot.GetValue<string>("userId");
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var refreshedExpiry = now + 600_000;

        await _sessions.Document(sessionId).UpdateAsync(new Dictionary<string, object>
        {
            ["lastUsedOn"] = now,
            ["expireOn"] = refreshedExpiry
        });

        return new SessionContext(sessionId, userId, key, refreshedExpiry);
    }

    private async Task<SessionContext> CreateSessionAsync(string userId, byte[] key)
    {
        var sessionId = PasswordCrypto.Base64UrlEncode(
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var expires = now + 600_000;

        await _sessions.Document(sessionId).SetAsync(new Dictionary<string, object>
        {
            ["userId"] = userId,
            ["key"] = PasswordCrypto.Base64UrlEncode(key),
            ["createdOn"] = now,
            ["lastUsedOn"] = now,
            ["expireOn"] = expires
        });

        return new SessionContext(sessionId, userId, key, expires);
    }

    public async Task CreatePasswordAsync(string pid, string password, SessionContext session)
    {
        var docId = PasswordCrypto.StableId(pid);
        var doc = _data.Document(session.UserId).Collection("passwords").Document(docId);
        if ((await doc.GetSnapshotAsync()).Exists)
            throw new ApiException(409, "'pID' used, Please use a unique pID");

        var encrypted = PasswordCrypto.Encrypt(password, session.Key);
        await doc.SetAsync(new Dictionary<string, object>
        {
            ["pID"] = pid,
            ["enc"] = new Dictionary<string, object>
            {
                ["cipher"] = encrypted.Cipher,
                ["iv"] = encrypted.Iv
            }
        });
    }

    public async Task<PasswordRecord> GetPasswordAsync(string pid, SessionContext session)
    {
        var doc = await PasswordDocument(session.UserId, pid).GetSnapshotAsync();
        if (!doc.Exists)
            throw new ApiException(400, "Given 'pID' not found");

        return new PasswordRecord(doc.Id, doc.GetValue<string>("pID"),
            PasswordCrypto.Decrypt(ReadEncrypted(doc), session.Key));
    }

    public async Task<IReadOnlyList<PasswordRecord>> GetAllPasswordsAsync(SessionContext session)
    {
        var snapshot = await _data.Document(session.UserId).Collection("passwords").GetSnapshotAsync();
        var result = new List<PasswordRecord>();
        foreach (var doc in snapshot.Documents)
        {
            result.Add(new PasswordRecord(doc.Id, doc.GetValue<string>("pID"),
                PasswordCrypto.Decrypt(ReadEncrypted(doc), session.Key)));
        }
        return result;
    }

    public async Task DeletePasswordAsync(string pid, SessionContext session)
    {
        var doc = PasswordDocument(session.UserId, pid);
        var snapshot = await doc.GetSnapshotAsync();
        if (!snapshot.Exists)
            throw new ApiException(400, "Given 'pID' not found");
        await doc.DeleteAsync();
    }

    public async Task UpdatePasswordAsync(string pid, string password, SessionContext session)
    {
        var doc = PasswordDocument(session.UserId, pid);
        var snapshot = await doc.GetSnapshotAsync();
        if (!snapshot.Exists)
            throw new ApiException(400, "Given 'pID' not found");

        var encrypted = PasswordCrypto.Encrypt(password, session.Key);
        await doc.UpdateAsync("enc", new Dictionary<string, object>
        {
            ["cipher"] = encrypted.Cipher,
            ["iv"] = encrypted.Iv
        });
    }

    public async Task UpdatePidAsync(string pid, string newPid, SessionContext session)
    {
        var oldRef = PasswordDocument(session.UserId, pid);
        var oldDoc = await oldRef.GetSnapshotAsync();
        if (!oldDoc.Exists)
            throw new ApiException(400, "Given 'pID' not found");

        var newRef = PasswordDocument(session.UserId, newPid);
        if ((await newRef.GetSnapshotAsync()).Exists)
            throw new ApiException(409, "'pID' used, Please use a unique pID");

        var encrypted = ReadEncrypted(oldDoc);
        await newRef.SetAsync(new Dictionary<string, object>
        {
            ["pID"] = newPid,
            ["enc"] = new Dictionary<string, object>
            {
                ["cipher"] = encrypted.Cipher,
                ["iv"] = encrypted.Iv
            }
        });
        await oldRef.DeleteAsync();
    }

    public async Task<int> ChangeMasterPasswordAsync(
        string newPassword, SessionContext session)
    {
        var userRef = _users.Document(session.UserId);
        var user = await userRef.GetSnapshotAsync();
        if (!user.Exists)
            throw new ApiException(400, "User not found");

        var newSalt = PasswordCrypto.NewSalt();
        var newKey = PasswordCrypto.DeriveKey(newPassword, newSalt);
        var passwordCollection = _data.Document(session.UserId).Collection("passwords");
        var snapshot = await passwordCollection.GetSnapshotAsync();
        var updated = 0;

        foreach (var doc in snapshot.Documents)
        {
            var plain = PasswordCrypto.Decrypt(ReadEncrypted(doc), session.Key);
            var encrypted = PasswordCrypto.Encrypt(plain, newKey);
            await doc.Reference.UpdateAsync("enc", new Dictionary<string, object>
            {
                ["cipher"] = encrypted.Cipher,
                ["iv"] = encrypted.Iv
            });
            updated++;
        }

        await userRef.UpdateAsync(new Dictionary<string, object>
        {
            ["passwordHash"] = BCrypt.HashPassword(newPassword, 10),
            ["keySalt"] = PasswordCrypto.Base64UrlEncode(newSalt)
        });
        await _sessions.Document(session.SessionId).UpdateAsync(
            "key", PasswordCrypto.Base64UrlEncode(newKey));

        return updated;
    }

    public async Task<string?> GetEmailAsync(string userId)
    {
        var doc = await _users.Document(userId).GetSnapshotAsync();
        return doc.Exists ? doc.GetValue<string>("email") : null;
    }

    private DocumentReference PasswordDocument(string userId, string pid) =>
        _data.Document(userId).Collection("passwords")
            .Document(PasswordCrypto.StableId(pid));

    private static EncryptedValue ReadEncrypted(DocumentSnapshot doc)
    {
        var map = doc.GetValue<Dictionary<string, object>>("enc");
        return new EncryptedValue((string)map["cipher"], (string)map["iv"]);
    }
}

public sealed class ApiException(int statusCode, string message) : Exception(message)
{
    public int StatusCode { get; } = statusCode;
}
