package org.bci.configurations;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.web.servlet.server.Encoding;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.apache.tomcat.util.http.fileupload.disk.DiskFileItem.DEFAULT_CHARSET;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.util.MimeTypeUtils.APPLICATION_JSON_VALUE;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
@Configuration
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest httpServletRequest,
                       HttpServletResponse httpServletResponse,
                       AccessDeniedException e) throws IOException, ServletException {

        ObjectMapper mapper = new ObjectMapper();
        httpServletResponse.setStatus(UNAUTHORIZED.value());
        httpServletResponse.setContentType(APPLICATION_JSON_VALUE);
        httpServletResponse.setCharacterEncoding(DEFAULT_CHARSET);
        httpServletResponse.getWriter().write(mapper.writeValueAsString(e.getMessage()));
    }
}
