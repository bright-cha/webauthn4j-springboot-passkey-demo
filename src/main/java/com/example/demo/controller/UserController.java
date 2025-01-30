package com.example.demo.controller;

import com.example.demo.dto.UserCreateForm;
import com.example.demo.service.UserService;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidationResponse;
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final UserService userService;
    private final WebAuthnRegistrationRequestValidator registrationRequestValidator;

    /**
     * 로그인/회원가입/로그아웃 페이지 요청
     */
    @GetMapping({"/login", "/signup"})
    public void pageMove() { }

    // 회원가입 요청 처리
    @PostMapping(value = "/signup")
    public String create(
            HttpServletRequest request,
            @ModelAttribute("userForm") UserCreateForm userCreateForm,
            BindingResult result,
            Model model,
            RedirectAttributes redirectAttributes
    ) {
        log.info("회원가입 요청.");
        try {
            if (result.hasErrors()) {
                model.addAttribute("errorMessage", "입력값을 확인해 주세요.");
                return "signup";
            }

            WebAuthnRegistrationRequestValidationResponse registrationResponse =
                    registrationRequestValidator.validate(
                            request,
                            userCreateForm.authenticator().clientDataJSON(),
                            userCreateForm.authenticator().attestationObject(),
                            userCreateForm.authenticator().transports(),
                            userCreateForm.authenticator().clientExtensions()
                    );

            // 사용자 등록 로직 처리...
            userService.save(userCreateForm.username(), userCreateForm.password());

        } catch (RuntimeException ex) {
            model.addAttribute("errorMessage", "예기치 않은 오류가 발생했습니다.");
            return "signup";
        }

        redirectAttributes.addFlashAttribute("successMessage", "회원가입이 완료되었습니다.");
        return "redirect:/login";
    }

}
