package com.example.demo.controller;

import com.example.demo.dto.UserDto;
import com.example.demo.dto.UserRequestDto;
import com.example.demo.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;

    /**
     * 로그인/회원가입/로그아웃 페이지 요청
     */
    @GetMapping({"/login", "/signup"})
    public void pageMove() { }

    /**
     * 회원가입 요청 처리
     * - 성공 시 로그인 페이지로 이동
     */
    @PostMapping("/signup")
    public String signup(@ModelAttribute UserRequestDto userRequestDto, Model model) {
        // 회원가입 처리
        UserDto newUser = userService.addUser(userRequestDto);

        // 회원가입 결과를 model 에 넣어서 signup.html 에서 메시지 처리하는 로직도 가능
        model.addAttribute("user", newUser);

        // 회원가입 성공 후 로그인 페이지로 리다이렉트
        return "redirect:/login";
    }
}
