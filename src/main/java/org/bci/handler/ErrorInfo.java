package org.bci.handler;

/**
 * @author ivan.graciarena
 * @project ivan-graciarena-bci-challenge
 */
public class ErrorInfo {
    public final String url;
    public final String ex;

    public ErrorInfo(String url, Exception ex) {
        this.url = url;
        this.ex = ex.getLocalizedMessage();
    }
}
