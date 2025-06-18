Secure "TaskHub" - A To-Do List ApplicationThis project guides you through building a secure RESTful API for a To-Do List application using Spring Boot. It starts with an unsecured foundation and progressively adds security features, including Basic Authentication, JWT-based authentication, and Role-Based Access Control (RBAC).Stage 1: Building the Foundation - An Unsecured TaskHub APIObjective: Create a simple Spring Boot application with basic CRUD (Create, Read, Update, Delete) functionality for tasks. At this stage, there will be no security.1. Conceptual OverviewBefore we secure an application, we first need an application to secure! In this initial stage, we will build a standard Spring Boot REST API. The core components are:Model/Entity: A Java class (Task) that represents the data we want to store. This class is mapped to a database table.Repository: An interface (extending Spring Data JPA's JpaRepository) that provides a set of pre-built methods for database operations like saving, finding, and deleting data. This abstracts away the boilerplate database interaction code.Controller: A Java class (TaskController) that defines the API endpoints (URLs). It handles incoming HTTP requests (like GET, POST, PUT, DELETE), processes them, and returns an HTTP response.Service (Optional but recommended): A class (TaskService) that sits between the Controller and the Repository. It contains the core business logic, helping to keep the Controller lean and focused on handling HTTP-related tasks.In-Memory Database (H2): For simplicity in this stage, we'll use H2, an in-memory database. This means our data will be available as long as the application is running and will be wiped clean on restart. This is perfect for development and testing, as it requires zero external configuration.2. Implementation StepsStep A: Create Your Spring Boot ProjectGo to start.spring.io.Fill in the project metadata:Project: Maven ProjectLanguage: JavaSpring Boot: Use a recent stable version (e.g., 3.x.x).Group: com.exampleArtifact: taskhubName: taskhubPackaging: JarJava: 17 or newerClick on "ADD DEPENDENCIES" and add the following:Spring Web: For building RESTful web applications.Spring Data JPA: To persist data in SQL stores with Java Persistence API using Spring Data and Hibernate.H2 Database: To provide an in-memory database.Click "GENERATE". This will download a .zip file.Unzip the file and open the project in your favorite IDE (like IntelliJ IDEA or VS Code).Step B: Review pom.xml DependenciesYour pom.xml file should contain these dependencies (versions might vary slightly):<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>
Step C: Create the Task EntityCreate a new package com.example.taskhub.model. Inside this package, create a Task.java file.// src/main/java/com/example/taskhub/model/Task.java
package com.example.taskhub.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class Task {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String title;
    private String description;
    private boolean completed;

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public boolean isCompleted() { return completed; }
    public void setCompleted(boolean completed) { this.completed = completed; }
}
Step D: Create the Task RepositoryCreate a new package com.example.taskhub.repository. Inside, create the TaskRepository.java interface.// src/main/java/com/example/taskhub/repository/TaskRepository.java
package com.example.taskhub.repository;

import com.example.taskhub.model.Task;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TaskRepository extends JpaRepository<Task, Long> {
}
```JpaRepository<Task, Long>` gives us all standard CRUD methods for the `Task` entity, which has a primary key of type `Long`.

#### Step E: Create the Task Service

Create a new package `com.example.taskhub.service`. Inside, create the `TaskService.java` class.

```java
// src/main/java/com/example/taskhub/service/TaskService.java
package com.example.taskhub.service;

import com.example.taskhub.model.Task;
import com.example.taskhub.repository.TaskRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;

@Service
public class TaskService {

    @Autowired
    private TaskRepository taskRepository;

    public List<Task> findAllTasks() {
        return taskRepository.findAll();
    }

    public Optional<Task> findTaskById(Long id) {
        return taskRepository.findById(id);
    }

    public Task saveTask(Task task) {
        return taskRepository.save(task);
    }

    public void deleteTask(Long id) {
        taskRepository.deleteById(id);
    }
}
Step F: Create the Task ControllerCreate a new package com.example.taskhub.controller. Inside, create the TaskController.java class.// src/main/java/com/example/taskhub/controller/TaskController.java
package com.example.taskhub.controller;

import com.example.taskhub.model.Task;
import com.example.taskhub.service.TaskService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/tasks")
public class TaskController {

    @Autowired
    private TaskService taskService;

    // Create a new task
    @PostMapping
    public Task createTask(@RequestBody Task task) {
        return taskService.saveTask(task);
    }

    // Get all tasks
    @GetMapping
    public List<Task> getAllTasks() {
        return taskService.findAllTasks();
    }

    // Get a single task by ID
    @GetMapping("/{id}")
    public ResponseEntity<Task> getTaskById(@PathVariable Long id) {
        return taskService.findTaskById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // Update a task
    @PutMapping("/{id}")
    public ResponseEntity<Task> updateTask(@PathVariable Long id, @RequestBody Task taskDetails) {
        return taskService.findTaskById(id)
                .map(task -> {
                    task.setTitle(taskDetails.getTitle());
                    task.setDescription(taskDetails.getDescription());
                    task.setCompleted(taskDetails.isCompleted());
                    Task updatedTask = taskService.saveTask(task);
                    return ResponseEntity.ok(updatedTask);
                }).orElse(ResponseEntity.notFound().build());
    }

    // Delete a task
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteTask(@PathVariable Long id) {
        return taskService.findTaskById(id)
                .map(task -> {
                    taskService.deleteTask(id);
                    return ResponseEntity.ok().build();
                }).orElse(ResponseEntity.notFound().build());
    }
}
3. Testing GuidanceRun your application. You can do this from your IDE or by running ./mvnw spring-boot:run in your terminal. Once the application starts (usually on port 8080), you can use Postman to test the endpoints.POST /api/tasks - Create a TaskMethod: POSTURL: http://localhost:8080/api/tasksBody: Select raw and JSON.JSON Content:{
    "title": "Learn Spring Boot",
    "description": "Complete the first stage of the project.",
    "completed": false
}
Expected Result: You should get a 200 OK response with the created task object, including its new id.GET /api/tasks - Get All TasksMethod: GETURL: http://localhost:8080/api/tasksExpected Result: You should see a JSON array containing the task you just created.GET /api/tasks/{id} - Get a Single TaskMethod: GETURL: http://localhost:8080/api/tasks/1 (replace 1 with the ID from the POST response).Expected Result: You should get the details of that specific task.PUT /api/tasks/{id} - Update a TaskMethod: PUTURL: http://localhost:8080/api/tasks/1Body: Select raw and JSON.JSON Content:{
    "title": "Learn Spring Boot - Stage 1",
    "description": "Complete the first stage of the project and test all endpoints.",
    "completed": true
}
Expected Result: You should get a 200 OK response with the updated task.DELETE /api/tasks/{id} - Delete a TaskMethod: DELETEURL: http://localhost:8080/api/tasks/1Expected Result: You should get a 200 OK response with an empty body. If you now try the "Get All Tasks" request again, the list should be empty.4. Code to ExpectBy the end of this stage, your project structure should contain the following key new files:pom.xml (with added dependencies)src/main/java/com/example/taskhub/model/Task.javasrc/main/java/com.example.taskhub/repository/TaskRepository.javasrc/main/java/com.example.taskhub/service/TaskService.javasrc/main/java/com.example.taskhub/controller/TaskController.javaYou have now successfully built the foundation of the TaskHub API. All endpoints are open and accessible without any authentication. In the next stage, we'll introduce Spring Security to lock these down.Stage 2: Implementing Basic Authentication - Securing EndpointsObjective: Add Spring Security to the project and secure all endpoints with basic username and password authentication. We will start with an in-memory user for simplicity.1. Detailed Conceptual OverviewWhy Do We Need Security?Right now, anyone who knows your API's address (http://localhost:8080/api/tasks) can create, view, update, and delete tasks. This is a massive security hole. We need to ensure that only legitimate, known users can interact with the data. This process of verifying a user's identity is called Authentication.How Spring Security Works: The Filter ChainWhen you add the Spring Security dependency, it inserts a chain of "filters" into your application's request processing path. Think of it like a series of security checkpoints at an airport.Incoming Request -> [Filter 1] -> [Filter 2] -> [Filter 3] -> ... -> Your ControllerEach filter has a specific job. One might check for a username/password, another might handle logout, and another might check for a specific security token. If any filter in the chain decides the request is not valid (e.g., missing password), it immediately rejects the request with an error (like 401 Unauthorized) and the request never even reaches your TaskController.HTTP Basic AuthenticationThis is one of the simplest authentication schemes. Here's the flow:The client (e.g., Postman) makes a request to a protected endpoint like GET /api/tasks.The server, protected by Spring Security, sees there are no credentials and responds with a 401 Unauthorized status and a WWW-Authenticate: Basic header. This tells the client, "You need to provide a username and password using the Basic Auth method."The client then re-sends the request, but this time includes an Authorization header. The value of this header is the string "Basic " followed by a base64-encoded version of username:password.The server receives this, decodes the credentials, and checks if they match a known user. If they match, the request is processed. If not, it's rejected again with a 401. Postman handles this encoding for us automatically when we use its "Basic Auth" feature.PasswordEncoder and BCryptWe never store passwords as plain text. If our database were ever compromised, all user passwords would be exposed. Instead, we store a "hash" of the password. A hashing function takes an input (the password) and produces a fixed-size string of characters that is nearly impossible to reverse.BCrypt is a very strong hashing algorithm because it is slow and includes a "salt" (a random value added to the password before hashing). This means that even if two users have the same password, their stored hashes will be different. When a user tries to log in, we take the password they provided, hash it using the same salt, and compare the result to the stored hash.2. Detailed Implementation StepsStep A: Add the Spring Security DependencyOpen your pom.xml file.Inside the <dependencies> section, add the following XML block:<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
Save the pom.xml file. Your IDE (like IntelliJ or VS Code) should automatically detect the change and download the necessary files. If not, right-click on pom.xml and find an option like "Maven" -> "Reload Project".Immediate Effect: If you run the application now, every single endpoint is protected. Trying to access GET /api/tasks will fail with a 401 Unauthorized error. This is Spring Security's "secure by default" principle. Now, we need to configure it.Step B: Create the Security Configuration ClassIn your project's source folder (src/main/java), navigate to your base package (com.example.taskhub).Create a new package named config.Inside the config package, create a new Java class named SecurityConfig.java.Now, add the following code to this file. The comments explain what each part does in detail.// src/main/java/com/example/taskhub/config/SecurityConfig.java
package com.example.taskhub.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

// @Configuration indicates that this class contains Spring configuration beans.
@Configuration
// @EnableWebSecurity enables Spring Security's web security support.
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Defines a bean for the PasswordEncoder. A bean is an object managed by Spring.
     * We use BCrypt, a strong hashing algorithm, to securely store passwords.
     * This bean can now be injected and used anywhere in our application.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Defines a bean for managing users. For this stage, we are using an
     * in-memory manager. It's a quick way to set up users without a database.
     * In later stages, we will replace this with a manager that reads from a database.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        // We create a 'user' with the role 'USER'.
        // The password "password" is encoded using the passwordEncoder bean.
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();

        // We create an 'admin' with the roles 'USER' and 'ADMIN'.
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("admin"))
                .roles("USER", "ADMIN")
                .build();
        
        // The InMemoryUserDetailsManager takes these user details and makes them available for authentication.
        return new InMemoryUserDetailsManager(user, admin);
    }

    /**
     * This is the core of our security configuration. It defines the SecurityFilterChain bean
     * which configures all security aspects for HTTP requests.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Start configuring authorization rules.
            .authorizeHttpRequests(auth -> auth
                // We specify that ANY request to our application requires the user to be authenticated.
                .anyRequest().authenticated()
            )
            // Configure HTTP Basic Authentication. 'withDefaults()' provides a standard configuration.
            .httpBasic(withDefaults())
            // CSRF (Cross-Site Request Forgery) protection is enabled by default. For stateless REST APIs
            // where the client is not a web browser, this is not necessary. We disable it here.
            .csrf(csrf -> csrf.disable()); 

        // Build and return the configured HttpSecurity object.
        return http.build();
    }
}
3. Detailed Testing GuidanceRestart your application for the new configuration to take effect. Open Postman to test our newly secured endpoints.Test 1: Unauthenticated Request (Expect 401 Unauthorized)Set up a new request for GET http://localhost:8080/api/tasks.Go to the Authorization tab.Make sure the Type is set to No Auth.Click Send.Expected Result:Status: 401 Unauthorized. This is Spring Security correctly blocking the request.Body: You might see a JSON error response from Spring Boot, like:{
    "timestamp": "...",
    "status": 401,
    "error": "Unauthorized",
    "path": "/api/tasks"
}
Headers: Look at the response headers. You will see one called WWW-Authenticate with the value Basic realm="Realm". This is the server's challenge to the client.Test 2: Authenticated Request with Correct Credentials (Expect 200 OK)Use the same request GET http://localhost:8080/api/tasks.Go to the Authorization tab.Change the Type from "No Auth" to Basic Auth.Two input fields for Username and Password will appear on the right.Enter the credentials for our in-memory user:Username: userPassword: passwordClick Send.Expected Result:Status: 200 OK. Success! You have been authenticated.Body: You will see the JSON response from your controller (an empty array [] if no tasks exist).Headers: If you check the request headers in Postman (under the "Headers" tab, not the response headers), you'll see that Postman has automatically added an Authorization header for you. Its value will look something like Basic dXNlcjpwYXNzd29yZA==. The cryptic part is just user:password encoded in Base64.Test 3: Try Other Endpoints and RolesChange the method to POST, keep the same Basic Auth credentials (user/password), and try to create a new task. It should work and return a 200 OK.Now, change the credentials in the Authorization tab to the admin user:Username: adminPassword: adminTry any request again. It should also work. At this stage, both USER and ADMIN can do everything, because our only rule is .anyRequest().authenticated(). We will restrict access based on roles in Stage 4.4. Code to Expect: A SummaryBy the end of this detailed stage, your project has two key modifications:pom.xml: Now contains the spring-boot-starter-security dependency.src/main/java/com/example/taskhub/config/SecurityConfig.java: A brand new configuration file that defines:How passwords are encoded (BCryptPasswordEncoder).Who the valid users are (InMemoryUserDetailsManager).What the security rules are (all requests need authentication via HTTP Basic).You have successfully locked down your API. While functional, Basic Auth is not ideal for modern applications.Stage 3: Introducing JWT for Stateless AuthenticationObjective: Replace the session-based Basic Authentication with a stateless JWT-based model. This is the standard for modern, scalable REST APIs.1. Detailed Conceptual OverviewWe are making a significant upgrade from Basic Auth. Let's break down the "why" and "how".Why JWT is Better than Basic Auth:Stateless: With Basic Auth, the server authenticates credentials on every single request. With JWT, the user logs in once. The server gives them a "token" (the JWT), which is like a temporary, digitally-signed ID card. For subsequent requests, the user just shows this ID card. The server only needs to check if the signature on the card is valid, not re-verify the original credentials. This removes the need for the server to store session information, making it highly scalable.Decoupled: Your frontend and backend are more independent. The frontend's only job is to get a token and include it in future requests. The backend doesn't care who the client is, as long as they present a valid token.Information Carrier: The JWT itself can securely carry information (called "claims"), such as the user's username and their roles (ROLE_USER, ROLE_ADMIN). This information can be trusted because it's part of the token's digital signature.The New Authentication Flow:User Registration: A new user will send their desired username and password to a public endpoint (POST /api/auth/register). We'll hash their password and save them to our database.User Login: The user sends their username and password to POST /api/auth/login.Token Generation: The server validates the credentials. If correct, it generates a JWT containing the user's name and an expiration date, signs it with a secret key, and sends it back.Token Storage: The client (e.g., a browser application) stores this token securely.Authenticated Requests: To access a protected endpoint like GET /api/tasks, the client adds an Authorization header to the request with the value Bearer <the_jwt_token>.Token Validation: Our new JwtAuthenticationFilter intercepts the request, extracts the token, validates its signature and expiration date using the secret key, and if valid, it tells Spring Security who the user is. The request then proceeds to the controller.2. Detailed Implementation StepsThis is a multi-step process involving new dependencies, new classes, and significant changes to our security configuration.Step A: Add JWT and Validation DependenciesWe need libraries to create/parse JWTs (jjwt) and to validate our request DTOs (validation). Open your pom.xml and add these dependencies:<!-- For JWT creation and validation -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>

<!-- For validating request bodies (e.g., non-empty username) -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
Remember to reload your Maven project after adding these.Step B: Create a Real User Entity and RepositoryOur in-memory user management won't work anymore; we need to store users in the database.Create the User Entity: In your com.example.taskhub.model package, create a User.java class.// src/main/java/com/example/taskhub/model/User.java
package com.example.taskhub.model;

import jakarta.persistence.*;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Entity
@Table(name = "app_user") // "user" is often a reserved keyword in SQL
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true)
    private String username;
    private String password;
    private String role; // e.g., "ROLE_USER" or "ROLE_ADMIN"

    // Getters and Setters for id, username, password, role...
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
    public void setUsername(String username) { this.username = username; }
    public void setPassword(String password) { this.password = password; }


    // UserDetails interface methods
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() { return true; }
    @Override
    public boolean isAccountNonLocked() { return true; }
    @Override
    public boolean isCredentialsNonExpired() { return true; }
    @Override
    public boolean isEnabled() { return true; }
}
Create the User Repository: In com.example.taskhub.repository, create UserRepository.java.// src/main/java/com/example/taskhub/repository/UserRepository.java
package com.example.taskhub.repository;

import com.example.taskhub.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
Step C: Create the JWT Utility ServiceThis class will contain all the logic for generating, parsing, and validating tokens.Create a new package com.example.taskhub.jwt.Inside, create a JwtUtil.java class.// src/main/java/com/example/taskhub/jwt/JwtUtil.java
package com.example.taskhub.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtil {

    // A secure key for signing the token. In production, this MUST be stored securely (e.g., in environment variables).
    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_TIME = 1000 * 60 * 60 * 10; // 10 hours

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY).compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
Step D: Create the JWT Authentication FilterThis custom filter will run for every request. It checks for the Bearer token and validates it.In the com.example.taskhub.jwt package, create JwtAuthenticationFilter.java.// src/main/java/com/example/taskhub/jwt/JwtAuthenticationFilter.java
package com.example.taskhub.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return; // Exit filter chain
        }

        jwt = authHeader.substring(7);
        username = jwtUtil.extractUsername(jwt);

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            if (jwtUtil.validateToken(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
Step E: Create DTOs and the Auth ControllerWe need Data Transfer Objects (DTOs) for our request/response bodies and a new controller to handle /register and /login.Create DTOs: Create a new package com.example.taskhub.dto.AuthRequest.java (for login)// src/main/java/com/example/taskhub/dto/AuthRequest.java
package com.example.taskhub.dto;
public class AuthRequest {
    private String username;
    private String password;
    // Getters and Setters
    public String getUsername() { return username; }
    public String getPassword() { return password; }
}
```AuthResponse.java` (for sending the token back)
```java
// src/main/java/com/example/taskhub/dto/AuthResponse.java
package com.example.taskhub.dto;
public class AuthResponse {
    private final String jwt;
    public AuthResponse(String jwt) { this.jwt = jwt; }
    // Getter
    public String getJwt() { return jwt; }
}
```RegisterRequest.java` (for user registration)
```java
// src/main/java/com/example/taskhub/dto/RegisterRequest.java
package com.example.taskhub.dto;
import jakarta.validation.constraints.NotEmpty;
public class RegisterRequest {
    @NotEmpty
    private String username;
    @NotEmpty
    private String password;
    // Getters and Setters
    public String getUsername() { return username; }
    public String getPassword() { return password; }
}
Create AuthController: In com.example.taskhub.controller, create AuthController.java.// src/main/java/com/example/taskhub/controller/AuthController.java
package com.example.taskhub.controller;

import com.example.taskhub.dto.AuthRequest;
import com.example.taskhub.dto.AuthResponse;
import com.example.taskhub.dto.RegisterRequest;
import com.example.taskhub.jwt.JwtUtil;
import com.example.taskhub.model.User;
import com.example.taskhub.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthRequest authRequest) throws Exception {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
        );
        final UserDetails userDetails = userRepository.findByUsername(authRequest.getUsername()).get();
        final String jwt = jwtUtil.generateToken(userDetails);
        return ResponseEntity.ok(new AuthResponse(jwt));
    }

    @PostMapping("/register")
    public ResponseEntity<?> saveUser(@RequestBody RegisterRequest registerRequest) throws Exception {
        if (userRepository.findByUsername(registerRequest.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Username is already taken");
        }
        User newUser = new User();
        newUser.setUsername(registerRequest.getUsername());
        newUser.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        newUser.setRole("ROLE_USER"); // Default role
        userRepository.save(newUser);
        return ResponseEntity.ok("User registered successfully");
    }
}
Step F: Update the Security Configuration (SecurityConfig.java)This is the final and most critical step, where we tie everything together.Modify your existing SecurityConfig.java class significantly.// src/main/java/com/example/taskhub/config/SecurityConfig.java
package com.example.taskhub.config;

import com.example.taskhub.jwt.JwtAuthenticationFilter;
import com.example.taskhub.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserRepository userRepository;

    @Autowired
    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter, UserRepository userRepository) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.userRepository = userRepository;
    }

    /**
     * Configures a custom UserDetailsService to fetch user details from the UserRepository.
     * It retrieves a user based on the provided username and throws a UsernameNotFoundException
     * if no such user exists. This service is crucial for Spring Security to authenticate users.
     *
     * @return UserDetailsService implementation for retrieving user details.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    /**
     * Defines a PasswordEncoder bean using BCryptPasswordEncoder, a strong hashing algorithm.
     * This encoder is used to hash and verify user passwords, ensuring secure storage.
     *
     * @return BCryptPasswordEncoder instance.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configures and returns an AuthenticationManager, which is responsible for authenticating
     * authentication requests. It delegates the actual authentication process to configured
     * AuthenticationProviders.
     *
     * @param config AuthenticationConfiguration object.
     * @return AuthenticationManager instance.
     * @throws Exception if an error occurs during authentication manager creation.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * This is the central method for configuring the security filter chain. It defines how
     * HTTP requests are secured and handled within the application.
     *
     * It performs the following key configurations:
     * <ol>
     * <li>Disables Cross-Site Request Forgery (CSRF) protection for API endpoints, as token-based
     * authentication (JWT) is used.</li>
     * <li>Configures authorization rules for incoming HTTP requests:
     * <ul>
     * <li>Permits all requests under the "/api/auth/**" path without authentication,
     * allowing access to authentication-related endpoints like login and registration.</li>
     * <li>Requires authentication for all other requests to the application.</li>
     * </ul>
     * </li>
     * <li>Sets the session management policy to STATELESS. This ensures that the application
     * does not create or use HTTP sessions, as JWTs are self-contained and handle
     * authentication state.</li>
     * <li>Integrates the custom JwtAuthenticationFilter into the Spring Security filter chain.
     * The {@code addFilterBefore} method ensures that the {@code JwtAuthenticationFilter}
     * is executed before the {@code UsernamePasswordAuthenticationFilter}. This allows
     * the JWT filter to intercept requests, validate the JWT, and set the authentication
     * context before the default username/password authentication mechanism is invoked.</li>
     * </ol>
     *
     * @param http HttpSecurity builder for configuring web security.
     * @return SecurityFilterChain configured security filter chain.
     * @throws Exception if an error occurs during security configuration.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
3. Detailed Testing GuidanceRestart your application. Your security model is now completely different.Test Registration (Public Endpoint)Method: POSTURL: http://localhost:8080/api/auth/registerAuthorization: No AuthBody (raw, JSON):{
    "username": "testuser",
    "password": "password123"
}
Result: 200 OK with the body "User registered successfully".Test Login (Public Endpoint)Method: POSTURL: http://localhost:8080/api/auth/loginAuthorization: No AuthBody (raw, JSON):{
    "username": "testuser",
    "password": "password123"
}
Result: 200 OK with a JSON body containing the JWT.{
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0dXNlciIsImlhdCI6MTY1..." // a very long string
}
Copy this entire JWT string.Test Access to Protected Endpoint (Expect 401/403 without token)Method: GETURL: http://localhost:8080/api/tasksAuthorization: No AuthResult: 403 Forbidden. (Spring Security 6+ often returns 403 instead of 401 for filter-level denials when no auth is provided). This is correct.Test Access to Protected Endpoint (With Bearer Token)Method: GETURL: http://localhost:8080/api/tasksGo to the Authorization tab.Select Type: Bearer Token.In the Token field on the right, paste the JWT you copied from the login step.Click Send.Result: 200 OK! You are now authenticated via your JWT and can access the protected resource.4. Code to ExpectThis was a big stage! You have created or heavily modified:pom.xml: Added jjwt and validation dependencies.New Model: User.javaNew Repository: UserRepository.javaNew DTOs: AuthRequest.java, AuthResponse.java, RegisterRequest.javaNew JWT classes: JwtUtil.java, JwtAuthenticationFilter.javaNew Controller: AuthController.javaHeavily Modified Config: SecurityConfig.javaYou have now implemented a robust, stateless authentication system. Next, we will build upon this by adding Role-Based Access Control (RBAC) to differentiate what a ROLE_USER can do versus a ROLE_ADMIN.Stage 4: Implementing Role-Based Access Control (RBAC)Objective: Introduce user roles (ROLE_USER, ROLE_ADMIN) and restrict access to certain endpoints and data based on these roles. This moves us from just authentication (who you are) to authorization (what you're allowed to do).Access Rules to Implement:ROLE_USER: Can create tasks, and can only read, update, or delete their own tasks.ROLE_ADMIN: Can perform any operation on any user's tasks.1. Detailed Conceptual OverviewAuthorization vs. Authentication:In the previous stages, we focused on Authentication - verifying a user's identity. Now we focus on Authorization - determining if that verified user has permission to perform a specific action.@PreAuthorize and Method-Level Security:While we can define access rules for URLs in our SecurityConfig (http.authorizeHttpRequests(...)), a more powerful and granular approach is method-level security. By adding the @PreAuthorize annotation directly to our controller or service methods, we can use Spring Expression Language (SpEL) to write complex authorization rules. For example, @PreAuthorize("hasRole('ADMIN')") ensures only admins can execute a method. A more complex rule like @PreAuthorize("#task.userId == authentication.principal.id or hasRole('ADMIN')") allows an action only if the user owns the object or is an admin.Passing Roles in JWT:To make authorization stateless, the user's roles must be included as a "claim" inside the JWT itself. When the JwtAuthenticationFilter validates the token, it will extract these roles and build an Authentication object that Spring Security can use for authorization checks. This avoids a database lookup for user roles on every request.Data Ownership:To implement the rule "users can only modify their own tasks," we must first establish ownership. This means our Task entity needs a field to store the ID of the User who created it.2. Detailed Implementation StepsStep A: Enable Method-Level SecurityFirst, we need to tell Spring Security to look for and enforce annotations like @PreAuthorize.In your SecurityConfig.java, add the @EnableMethodSecurity annotation to the class.// src/main/java/com/example/taskhub/config/SecurityConfig.java

//... other imports
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // <-- ADD THIS ANNOTATION
public class SecurityConfig {
    // ... rest of the class
}
Step B: Add Ownership to the Task EntityModify the Task.java model to include a reference to the user who owns it.// src/main/java/com/example/taskhub/model/Task.java
package com.example.taskhub.model;

import jakarta.persistence.*;

@Entity
public class Task {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String title;
    private String description;
    private boolean completed;

    // --- NEW FIELD ---
    // Stores the ID of the user who owns this task.
    @Column(nullable = false)
    private Long userId;
    // --- END NEW FIELD ---


    // Getters and Setters for all fields, including the new userId field
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public boolean isCompleted() { return completed; }
    public void setCompleted(boolean completed) { this.completed = completed; }
    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
}
Step C: Update TaskRepositoryAdd a method to find all tasks belonging to a specific user.// src/main/java/com/example/taskhub/repository/TaskRepository.java
package com.example.taskhub.repository;

import com.example.taskhub.model.Task;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List; // <-- Import List

@Repository
public interface TaskRepository extends JpaRepository<Task, Long> {
    // --- NEW METHOD ---
    // Finds all tasks associated with a given user ID.
    List<Task> findByUserId(Long userId);
    // --- END NEW METHOD ---
}
Step D: Update JWT Generation to Include RolesModify JwtUtil.java to add the user's roles as a claim when generating a token.// src/main/java/com/example/taskhub/jwt/JwtUtil.java
package com.example.taskhub.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class JwtUtil {

    private static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_TIME = 1000 * 60 * 60 * 10; // 10 hours

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        // --- NEW ---
        // Add roles to the claims
        String roles = userDetails.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.joining(","));
        claims.put("roles", roles);
        // --- END NEW ---
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims) // The claims map now includes roles
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SECRET_KEY).compact();
    }
    
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
Note: We extract the roles from the UserDetails object, which already has them from our User entity.Step E: Create an Admin Registration EndpointFor testing, let's add a way to create an admin user. Modify AuthController.java.// src/main/java/com/example/taskhub/controller/AuthController.java
package com.example.taskhub.controller;

import com.example.taskhub.dto.AuthRequest;
import com.example.taskhub.dto.AuthResponse;
import com.example.taskhub.dto.RegisterRequest;
import com.example.taskhub.jwt.JwtUtil;
import com.example.taskhub.model.User;
import com.example.taskhub.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthRequest authRequest) throws Exception {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
        );
        final UserDetails userDetails = userRepository.findByUsername(authRequest.getUsername()).get();
        final String jwt = jwtUtil.generateToken(userDetails);
        return ResponseEntity.ok(new AuthResponse(jwt));
    }

    @PostMapping("/register")
    public ResponseEntity<?> saveUser(@RequestBody RegisterRequest registerRequest) throws Exception {
        // This existing endpoint will register users with ROLE_USER
        return registerUserWithRole(registerRequest, "ROLE_USER");
    }
    
    // --- NEW ENDPOINT ---
    @PostMapping("/register-admin")
    public ResponseEntity<?> saveAdmin(@RequestBody RegisterRequest registerRequest) throws Exception {
        // This new endpoint will register users with ROLE_ADMIN
        return registerUserWithRole(registerRequest, "ROLE_ADMIN");
    }
    // --- END NEW ENDPOINT ---
    
    private ResponseEntity<?> registerUserWithRole(RegisterRequest registerRequest, String role) {
        if (userRepository.findByUsername(registerRequest.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Username is already taken");
        }
        User newUser = new User();
        newUser.setUsername(registerRequest.getUsername());
        newUser.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        newUser.setRole(role); // Set the role dynamically
        userRepository.save(newUser);
        return ResponseEntity.ok("User registered successfully as " + role);
    }
}
Step F: Apply Authorization Rules to TaskController and TaskServiceThis is where we enforce our access rules. We will make significant changes to TaskService and TaskController.Modify TaskService.java// src/main/java/com/example/taskhub/service/TaskService.java
package com.example.taskhub.service;

import com.example.taskhub.model.Task;
import com.example.taskhub.model.User;
import com.example.taskhub.repository.TaskRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;

@Service
public class TaskService {

    @Autowired
    private TaskRepository taskRepository;

    // An Admin can find all tasks. A User will get an empty list (or forbidden, depending on controller).
    @PreAuthorize("hasRole('ADMIN')")
    public List<Task> findAllTasks() {
        return taskRepository.findAll();
    }

    // A User can find all of their own tasks.
    public List<Task> findTasksByCurrentUser() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return taskRepository.findByUserId(user.getId());
    }

    // A user can only view a task if they own it, or if they are an admin.
    @PreAuthorize("#task.userId == authentication.principal.id or hasRole('ADMIN')")
    public Optional<Task> findTaskIfAuthorized(Task task) {
         return Optional.of(task);
    }

    public Optional<Task> findTaskById(Long id) {
        return taskRepository.findById(id);
    }

    public Task saveTask(Task task) {
        // If the task is new, set its owner to the current user.
        if (task.getUserId() == null) {
            User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            task.setUserId(user.getId());
        }
        return taskRepository.save(task);
    }

    // A user can only delete a task if they own it, or if they are an admin.
    @PreAuthorize("#task.userId == authentication.principal.id or hasRole('ADMIN')")
    public void deleteTask(Task task) {
        taskRepository.deleteById(task.getId());
    }
}
Modify TaskController.java// src/main/java/com/example/taskhub/controller/TaskController.java
package com.example.taskhub.controller;

import com.example.taskhub.model.Task;
import com.example.taskhub.model.User;
import com.example.taskhub.service.TaskService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/tasks")
public class TaskController {

    @Autowired
    private TaskService taskService;

    // Anyone can create a task for themselves. The service sets the owner.
    @PostMapping
    public Task createTask(@RequestBody Task task) {
        return taskService.saveTask(task);
    }

    // ROLE_USER: Gets their own tasks.
    // ROLE_ADMIN: This endpoint is not for them, they should use /all.
    @GetMapping
    @PreAuthorize("hasRole('USER')")
    public List<Task> getMyTasks() {
        return taskService.findTasksByCurrentUser();
    }

    // ROLE_ADMIN: Gets all tasks from all users.
    @GetMapping("/all")
    @PreAuthorize("hasRole('ADMIN')")
    public List<Task> getAllTasks() {
        return taskService.findAllTasks();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Task> getTaskById(@PathVariable Long id) {
        // First, find the task. Then, check if the user is authorized to see it.
        return taskService.findTaskById(id)
                .flatMap(task -> taskService.findTaskIfAuthorized(task))
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping("/{id}")
    public ResponseEntity<Task> updateTask(@PathVariable Long id, @RequestBody Task taskDetails, @AuthenticationPrincipal User user) {
        // First find the task, then let the service layer check for permission before updating.
        return taskService.findTaskById(id)
                .map(task -> {
                    // Manually trigger @PreAuthorize check by calling a service method on the object
                    taskService.findTaskIfAuthorized(task).orElseThrow(() -> new SecurityException("Access Denied"));

                    task.setTitle(taskDetails.getTitle());
                    task.setDescription(taskDetails.getDescription());
                    task.setCompleted(taskDetails.isCompleted());
                    Task updatedTask = taskService.saveTask(task);
                    return ResponseEntity.ok(updatedTask);
                }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteTask(@PathVariable Long id) {
         return taskService.findTaskById(id)
                .map(task -> {
                    // The @PreAuthorize on deleteTask in the service layer will handle the security check.
                    taskService.deleteTask(task);
                    return ResponseEntity.ok().build();
                }).orElse(ResponseEntity.notFound().build());
    }
}
3. Detailed Testing GuidanceRestart your application. Your H2 database will be fresh.Register an Admin:POST /api/auth/register-adminBody: {"username": "adminuser", "password": "password"}Login as adminuser and get the JWT.Register a regular User:POST /api/auth/registerBody: {"username": "normaluser", "password": "password"}Login as normaluser and get their JWT.Create Tasks:As normaluser (using their Bearer Token), POST /api/tasks with a body like {"title": "User's Task"}. Note the ID, e.g., 1.As adminuser (using their Bearer Token
