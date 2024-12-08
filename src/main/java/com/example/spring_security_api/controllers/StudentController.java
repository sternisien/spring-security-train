package com.example.spring_security_api.controllers;


import jakarta.servlet.http.HttpServletRequest;
import com.example.spring_security_api.models.Student;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping
public class StudentController {


    List<Student> students  =  new ArrayList<>(List.of(new Student(1, "sébastien", 60), new Student(2, "florian", 90)));

    @GetMapping(value = "/csrf" )
    public CsrfToken getCsrfToken(HttpServletRequest servletRequest){
        return (CsrfToken) servletRequest.getAttribute("_csrf");
    }

    @GetMapping(value = "/students")
    public List<Student> getStudents(){
        return students;
    }

    @PostMapping(value = "/students")
    public Student createStudent(@RequestBody Student newStudent){
        students.add(newStudent);
        return newStudent;
    }
}
