using UnityEngine;
using UnityEngine.Networking;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace GunDrive.Auth
{
    [Serializable]
    public class AuthResponse
    {
        public bool success;
        public string token;
        public UserData user;
        public string error;
        public string message;
    }

    [Serializable]
    public class UserData
    {
        public string id;
        public string email;
        public string deviceId;
        public List<DeviceInfo> devices;
    }

    [Serializable]
    public class DeviceInfo
    {
        public string deviceId;
        public string deviceName;
        public string lastActiveAt;
        public string addedAt;
    }

    [Serializable]
    public class DevicesResponse
    {
        public bool success;
        public List<DeviceInfo> devices;
        public string currentDeviceId;
        public string error;
    }

    [Serializable]
    public class RegisterData
    {
        public string email;
        public string password;
        public string deviceId;
        public string deviceName;
    }

    [Serializable]
    public class LoginData
    {
        public string email;
        public string password;
        public string deviceId;
        public string deviceName;
    }

    public static class AuthManager
    {
        private static string serverUrl = "http://localhost:3000/api/auth";
        private static string _authToken;

        public static string AuthToken
        {
            get => _authToken;
            private set
            {
                _authToken = value;
                if (!string.IsNullOrEmpty(value))
                {
                    PlayerPrefs.SetString("AuthToken", value);
                    PlayerPrefs.Save();
                }
            }
        }

        public static string CurrentUserId { get; private set; }
        public static string CurrentUserEmail { get; private set; }
        public static string CurrentDeviceId => SystemInfo.deviceUniqueIdentifier;

        // Initialize - Load saved token
        public static void Initialize()
        {
            _authToken = PlayerPrefs.GetString("AuthToken", "");
        }

        public static IEnumerator Register(string email, string password, Action<bool, string> callback)
        {
            var data = new RegisterData
            {
                email = email,
                password = password,
                deviceId = SystemInfo.deviceUniqueIdentifier,
                deviceName = SystemInfo.deviceName
            };

            string json = JsonUtility.ToJson(data);
            byte[] bodyRaw = Encoding.UTF8.GetBytes(json);

            using (UnityWebRequest request = new UnityWebRequest($"{serverUrl}/register", "POST"))
            {
                request.uploadHandler = new UploadHandlerRaw(bodyRaw);
                request.downloadHandler = new DownloadHandlerBuffer();
                request.SetRequestHeader("Content-Type", "application/json");

                yield return request.SendWebRequest();

                if (request.result == UnityWebRequest.Result.Success)
                {
                    try
                    {
                        AuthResponse response = JsonUtility.FromJson<AuthResponse>(request.downloadHandler.text);
                        if (response.success && response.user != null)
                        {
                            AuthToken = response.token;
                            CurrentUserId = response.user.id;
                            CurrentUserEmail = response.user.email;
                            callback(true, "Registration successful");
                        }
                        else
                        {
                            callback(false, response.error ?? "Registration failed");
                        }
                    }
                    catch (Exception e)
                    {
                        callback(false, $"Error parsing response: {e.Message}");
                    }
                }
                else
                {
                    // Handle HTTP errors
                    if (request.responseCode == 409)
                    {
                        callback(false, "User already exists");
                    }
                    else
                    {
                        callback(false, $"Network error: {request.error}");
                    }
                }
            }
        }

        public static IEnumerator Login(string email, string password, Action<bool, string> callback)
        {
            var data = new LoginData
            {
                email = email,
                password = password,
                deviceId = SystemInfo.deviceUniqueIdentifier,
                deviceName = SystemInfo.deviceName
            };

            string json = JsonUtility.ToJson(data);
            byte[] bodyRaw = Encoding.UTF8.GetBytes(json);

            using (UnityWebRequest request = new UnityWebRequest($"{serverUrl}/login", "POST"))
            {
                request.uploadHandler = new UploadHandlerRaw(bodyRaw);
                request.downloadHandler = new DownloadHandlerBuffer();
                request.SetRequestHeader("Content-Type", "application/json");

                yield return request.SendWebRequest();

                if (request.result == UnityWebRequest.Result.Success)
                {
                    try
                    {
                        AuthResponse response = JsonUtility.FromJson<AuthResponse>(request.downloadHandler.text);
                        if (response.success && response.user != null)
                        {
                            AuthToken = response.token;
                            CurrentUserId = response.user.id;
                            CurrentUserEmail = response.user.email;
                            callback(true, "Login successful");
                        }
                        else
                        {
                            callback(false, response.error ?? "Login failed");
                        }
                    }
                    catch (Exception e)
                    {
                        callback(false, $"Error parsing response: {e.Message}");
                    }
                }
                else
                {
                    // Handle HTTP errors
                    if (request.responseCode == 401)
                    {
                        callback(false, "Invalid credentials");
                    }
                    else if (request.responseCode == 403)
                    {
                        callback(false, "Account is deactivated");
                    }
                    else
                    {
                        callback(false, $"Network error: {request.error}");
                    }
                }
            }
        }

        public static IEnumerator VerifyToken(Action<bool> callback)
        {
            string token = AuthToken;

            if (string.IsNullOrEmpty(token))
            {
                callback(false);
                yield break;
            }

            using (UnityWebRequest request = UnityWebRequest.Get($"{serverUrl}/verify"))
            {
                request.SetRequestHeader("Authorization", $"Bearer {token}");
                request.SetRequestHeader("Content-Type", "application/json");

                yield return request.SendWebRequest();

                if (request.result == UnityWebRequest.Result.Success)
                {
                    try
                    {
                        AuthResponse response = JsonUtility.FromJson<AuthResponse>(request.downloadHandler.text);
                        if (response.success && response.user != null)
                        {
                            CurrentUserId = response.user.id;
                            CurrentUserEmail = response.user.email;
                            callback(true);
                        }
                        else
                        {
                            ClearAuth();
                            callback(false);
                        }
                    }
                    catch
                    {
                        callback(false);
                    }
                }
                else
                {
                    if (request.responseCode == 403)
                    {
                        ClearAuth();
                    }
                    callback(false);
                }
            }
        }

        public static IEnumerator GetDevices(Action<bool, List<DeviceInfo>> callback)
        {
            string token = AuthToken;

            if (string.IsNullOrEmpty(token))
            {
                callback(false, null);
                yield break;
            }

            using (UnityWebRequest request = UnityWebRequest.Get($"{serverUrl}/devices"))
            {
                request.SetRequestHeader("Authorization", $"Bearer {token}");

                yield return request.SendWebRequest();

                if (request.result == UnityWebRequest.Result.Success)
                {
                    try
                    {
                        DevicesResponse response = JsonUtility.FromJson<DevicesResponse>(request.downloadHandler.text);
                        if (response.success)
                        {
                            callback(true, response.devices);
                        }
                        else
                        {
                            callback(false, null);
                        }
                    }
                    catch
                    {
                        callback(false, null);
                    }
                }
                else
                {
                    callback(false, null);
                }
            }
        }

        public static IEnumerator RemoveDevice(string deviceId, Action<bool, string> callback)
        {
            string token = AuthToken;

            if (string.IsNullOrEmpty(token))
            {
                callback(false, "Not authenticated");
                yield break;
            }

            using (UnityWebRequest request = UnityWebRequest.Delete($"{serverUrl}/devices/{deviceId}"))
            {
                request.SetRequestHeader("Authorization", $"Bearer {token}");

                yield return request.SendWebRequest();

                if (request.result == UnityWebRequest.Result.Success)
                {
                    try
                    {
                        AuthResponse response = JsonUtility.FromJson<AuthResponse>(request.downloadHandler.text);
                        callback(response.success, response.message ?? response.error);
                    }
                    catch
                    {
                        callback(false, "Error parsing response");
                    }
                }
                else
                {
                    if (request.responseCode == 400)
                    {
                        callback(false, "Cannot remove current device");
                    }
                    else
                    {
                        callback(false, $"Network error: {request.error}");
                    }
                }
            }
        }

        public static IEnumerator Logout(Action<bool, string> callback)
        {
            string token = AuthToken;

            if (string.IsNullOrEmpty(token))
            {
                callback(false, "Not authenticated");
                yield break;
            }

            using (UnityWebRequest request = new UnityWebRequest($"{serverUrl}/logout", "POST"))
            {
                request.downloadHandler = new DownloadHandlerBuffer();
                request.SetRequestHeader("Authorization", $"Bearer {token}");
                request.SetRequestHeader("Content-Type", "application/json");

                yield return request.SendWebRequest();

                if (request.result == UnityWebRequest.Result.Success)
                {
                    try
                    {
                        AuthResponse response = JsonUtility.FromJson<AuthResponse>(request.downloadHandler.text);
                        if (response.success)
                        {
                            ClearAuth();
                            callback(true, response.message ?? "Logged out successfully");
                        }
                        else
                        {
                            callback(false, response.error ?? "Logout failed");
                        }
                    }
                    catch
                    {
                        // Even if parsing fails, clear local auth
                        ClearAuth();
                        callback(true, "Logged out");
                    }
                }
                else
                {
                    // Clear local auth even on network failure
                    ClearAuth();
                    callback(true, "Logged out locally");
                }
            }
        }

        public static IEnumerator LogoutAll(Action<bool, string> callback)
        {
            string token = AuthToken;

            if (string.IsNullOrEmpty(token))
            {
                callback(false, "Not authenticated");
                yield break;
            }

            using (UnityWebRequest request = new UnityWebRequest($"{serverUrl}/logout-all", "POST"))
            {
                request.downloadHandler = new DownloadHandlerBuffer();
                request.SetRequestHeader("Authorization", $"Bearer {token}");
                request.SetRequestHeader("Content-Type", "application/json");

                yield return request.SendWebRequest();

                if (request.result == UnityWebRequest.Result.Success)
                {
                    try
                    {
                        AuthResponse response = JsonUtility.FromJson<AuthResponse>(request.downloadHandler.text);
                        if (response.success)
                        {
                            ClearAuth();
                            callback(true, response.message ?? "Logged out from all devices");
                        }
                        else
                        {
                            callback(false, response.error ?? "Logout failed");
                        }
                    }
                    catch
                    {
                        ClearAuth();
                        callback(true, "Logged out");
                    }
                }
                else
                {
                    ClearAuth();
                    callback(true, "Logged out locally");
                }
            }
        }

        private static void ClearAuth()
        {
            AuthToken = "";
            CurrentUserId = "";
            CurrentUserEmail = "";
            PlayerPrefs.DeleteKey("AuthToken");
            PlayerPrefs.Save();
        }

        // Helper method to check if user is authenticated
        public static bool IsAuthenticated()
        {
            return !string.IsNullOrEmpty(AuthToken);
        }

        // Configure server URL (useful for different environments)
        public static void SetServerUrl(string url)
        {
            serverUrl = url.TrimEnd('/') + "/api/auth";
        }
    }
}