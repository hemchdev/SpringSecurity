### **TaskHub - Spring Security**

This guide provides all the necessary requests and JSON bodies to test the role-based access control functionality.

### **Part 1: Authentication Endpoints**

These endpoints are for creating users and getting JWTs. Authorization for these requests should always be set to **`No Auth`**.

#### **1. Register a Regular User**

- **Method:** `POST`
    
- **URL:** `http://localhost:8080/api/auth/register`
    
- **Body (raw, JSON):**
    
    ```
    {
        "username": "normaluser",
        "password": "password123"
    }
    ```
    

#### **2. Register an Admin User**

- **Method:** `POST`
    
- **URL:** `http://localhost:8080/api/auth/register-admin`
    
- **Body (raw, JSON):**
    
    ```
    {
        "username": "adminuser",
        "password": "password123"
    }
    ```
    

#### **3. Login (for any user)**

- **Method:** `POST`
    
- **URL:** `http://localhost:8080/api/auth/login`
    
- **Body (raw, JSON):**
    
    ```
    {
        "username": "normaluser",
        "password": "password123"
    }
    ```
    
- **Action:** After sending, copy the `jwt` value from the response body. You will use this as a Bearer Token for authenticated requests. Repeat this process for `adminuser` to get their token as well.
    

### **Part 2: Task Management Endpoints**

For these requests, you must set the Authorization.

- **Go to the `Authorization` tab.**
    
- **Type:** `Bearer Token`.
    
- **Paste the user's JWT** into the "Token" field.
    

#### **1. Create a New Task**

- **Who can use:** Any authenticated user (`normaluser` or `adminuser`).
    
- **Method:** `POST`
    
- **URL:** `http://localhost:8080/api/tasks`
    
- **Authorization:** Bearer Token (e.g., from `normaluser`)
    
- **Body (raw, JSON):**
    
    ```
    {
        "title": "My First Task",
        "description": "Complete testing for Stage 4",
        "completed": false
    }
    ```
    
- **Action:** Create one task as `normaluser` and another as `adminuser`. Note the `id` of each task from the responses.
    

#### **2. Get My Tasks (for ROLE_USER)**

- **Who can use:** `normaluser` only.
    
- **Method:** `GET`
    
- **URL:** `http://localhost:8080/api/tasks`
    
- **Authorization:** Bearer Token (from `normaluser`)
    
- **Result:** You should see a list containing only the tasks created by `normaluser`.
    

#### **3. Get All Tasks (for ROLE_ADMIN)**

- **Who can use:** `adminuser` only.
    
- **Method:** `GET`
    
- **URL:** `http://localhost:8080/api/tasks/all`
    
- **Authorization:** Bearer Token (from `adminuser`)
    
- **Result:** You should see a list of ALL tasks, created by both `normaluser` and `adminuser`.
    

#### **4. Get a Specific Task by ID**

- **Who can use:** `adminuser` (for any task), `normaluser` (only for their own tasks).
    
- **Method:** `GET`
    
- **URL:** `http://localhost:8080/api/tasks/{id}` (replace `{id}` with a real task ID)
    
- **Authorization:** Bearer Token
    
- **Test Cases:**
    
    - `normaluser` requests their own task ID -> **Success (200 OK)**
        
    - `normaluser` requests the admin's task ID -> **Failure (404 Not Found)**
        
    - `adminuser` requests the normal user's task ID -> **Success (200 OK)**
        

#### **5. Update a Task**

- **Who can use:** `adminuser` (for any task), `normaluser` (only for their own tasks).
    
- **Method:** `PUT`
    
- **URL:** `http://localhost:8080/api/tasks/{id}` (replace `{id}` with a real task ID)
    
- **Authorization:** Bearer Token
    
- **Body (raw, JSON):**
    
    ```
    {
        "title": "Updated Task Title",
        "description": "This task has now been updated.",
        "completed": true
    }
    
    ```
    
- **Test Cases:**
    
    - `normaluser` updates their own task ID -> **Success (200 OK)**
        
    - `normaluser` updates the admin's task ID -> **Failure (404 Not Found)**
        
    - `adminuser` updates the normal user's task ID -> **Success (200 OK)**
        

#### **6. Delete a Task**

- **Who can use:** `adminuser` (for any task), `normaluser` (only for their own tasks).
    
- **Method:** `DELETE`
    
- **URL:** `http://localhost:8080/api/tasks/{id}` (replace `{id}` with a real task ID)
    
- **Authorization:** Bearer Token
    
- **Test Cases:**
    
    - `normaluser` deletes their own task ID -> **Success (200 OK)**
        
    - `normaluser` deletes the admin's task ID -> **Failure (404 Not Found)**
        
    - `adminuser` deletes the normal user's task ID -> **Success (200 OK)**
