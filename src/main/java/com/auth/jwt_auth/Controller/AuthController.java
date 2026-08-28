package com.auth.jwt_auth.Controller;


import com.auth.jwt_auth.Response.LoginResponse;
import com.auth.jwt_auth.entity.User;
import com.auth.jwt_auth.repository.UserRepository;
import com.auth.jwt_auth.security.JwtUnit;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.annotation.JsonAppend;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager ;

    @Autowired
    JwtUnit jwtUnit ;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    UserRepository userRepository ;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody User user){

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        user.getUsername() ,
                        user.getPassword()
                )
        );
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String token = jwtUnit.generateSecretKey(userDetails.getUsername()) ;

        LoginResponse loginResponse = new LoginResponse(
                token ,
                userDetails.getUsername()

        );



        return ResponseEntity.status(HttpStatus.OK).body(loginResponse);

    }

    @PostMapping("register")
    public ResponseEntity<User> registerUser(@RequestBody User user){
        if(userRepository.existsByUsername(user.getUsername())){
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).build();
        }

        User newUser = new User(
                null ,
                user.getUsername(),
                passwordEncoder.encode(user.getPassword())
        );

        userRepository.save(newUser);

        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }

}
