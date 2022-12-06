package study.resourceserver.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import study.resourceserver.dto.PhotoDto;

@RestController
@RequestMapping("/photos")
public class PhotoController {

    @GetMapping("/1")
    public PhotoDto photo1() {
        return PhotoDto.builder()
                .photoId("2")
                .title("title1")
                .description("good")
                .userId("user1")
                .build();
    }

    @GetMapping("/2")
    @PreAuthorize("hasAnyAuthority('SCOPE_photo')")
    public PhotoDto photo2() {
        return PhotoDto.builder()
                .photoId("2")
                .title("title2")
                .description("very good")
                .userId("user2")
                .build();
    }

    @GetMapping("/3")
    @PreAuthorize("hasAnyAuthority('ROLE_default-roles-oauth2')")
    public PhotoDto photo3() {
        return PhotoDto.builder()
                .photoId("3")
                .title("title3")
                .description("very bad")
                .userId("user3")
                .build();
    }
}
