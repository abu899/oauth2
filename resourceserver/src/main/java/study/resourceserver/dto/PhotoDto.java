package study.resourceserver.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PhotoDto {

    private String userId;
    private String photoId;
    private String title;
    private String description;
}
