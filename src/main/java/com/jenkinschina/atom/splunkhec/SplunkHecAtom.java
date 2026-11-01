package com.jenkinschina.atom.splunkhec;

import com.jenkinschina.atom.sdk.AtomContext;
import com.jenkinschina.atom.sdk.AtomResult;
import com.jenkinschina.atom.sdk.AtomTask;
import com.jenkinschina.atom.sdk.ErrorType;
import com.jenkinschina.atom.sdk.Json;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Sends one build event to a Splunk HTTP Event Collector.
 *
 * <p>splunk-devops posts build results to {@code /services/collector/event} with a {@code Splunk <token>}
 * header; this is that request, with the envelope spelled out. The important part is the answer: HEC replies 200
 * even when it rejects an event, and the verdict is in {@code code} — 0 accepted, everything else refused. A
 * sender that only looks at the status code reports success for events Splunk threw away.
 */
public class SplunkHecAtom implements AtomTask {

    @Override
    public AtomResult run(AtomContext context) throws Exception {
        String baseUrl = context.getParam("url", "").trim();
        String token = context.getSecret("token");
        if (token == null || token.isBlank()) {
            token = context.getParam("token", "");
        }
        String sourcetype = context.getParam("sourcetype", "jenkins").trim();
        String source = context.getParam("source", "jenkins").trim();
        String host = context.getParam("host", "").trim();
        String channel = context.getParam("channel", "").trim();
        String eventParam = context.getParam("event", "").trim();
        boolean raw = "raw".equalsIgnoreCase(context.getParam("mode", "event").trim());
        int timeoutSeconds = Math.max(5, Math.min(context.getIntParam("timeoutSeconds", 30), 300));

        if (baseUrl.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40001, "url is required (e.g. https://splunk.example.com:8088)");
        }
        if (token.isBlank()) {
            return AtomResult.error(ErrorType.USER, 40002, "token is required (a Splunk HEC token)");
        }

        String payload;
        if (raw) {
            // raw mode posts the text as-is; the caller decides what Splunk should index
            if (eventParam.isEmpty()) {
                return AtomResult.error(ErrorType.USER, 40003, "mode=raw needs event (the text to index)");
            }
            payload = "event=" + encode(eventParam)
                    + (sourcetype.isEmpty() ? "" : "&sourcetype=" + encode(sourcetype))
                    + (source.isEmpty() ? "" : "&source=" + encode(source))
                    + (host.isEmpty() ? "" : "&host=" + encode(host));
        } else {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("event", eventObject(context, eventParam));
            body.put("time", String.valueOf(System.currentTimeMillis() / 1000));
            if (!sourcetype.isEmpty()) {
                body.put("sourcetype", sourcetype);
            }
            if (!source.isEmpty()) {
                body.put("source", source);
            }
            if (!host.isEmpty()) {
                body.put("host", host);
            }
            if (!channel.isEmpty()) {
                body.put("channel", channel);
            }
            payload = Json.write(body);
        }

        String endpoint = baseUrl.replaceAll("/+$", "")
                + (raw ? "/services/collector/raw" : "/services/collector/event");
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(timeoutSeconds)).build();
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(endpoint))
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .header("Authorization", "Splunk " + token)
                .header("Content-Type", raw ? "application/x-www-form-urlencoded" : "application/json")
                .header("User-Agent", "jenkins-atom-splunk-hec")
                .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8));
        HttpResponse<String> response = client.send(request.build(), HttpResponse.BodyHandlers.ofString());

        String body = response.body() == null ? "" : response.body();
        Map<?, ?> answer = asMap(body);
        String code = text(answer, "code");
        String message = text(answer, "text");

        if (response.statusCode() == 401 || response.statusCode() == 403
                || "4".equals(code) || body.toLowerCase(Locale.ROOT).contains("token")) {
            return AtomResult.error(ErrorType.USER, 40004,
                    "Splunk refused the token: HTTP " + response.statusCode()
                            + (message.isEmpty() ? "" : " " + message));
        }
        if (response.statusCode() >= 300) {
            return AtomResult.error(ErrorType.THIRD_PART, 40005, "Splunk answered HTTP " + response.statusCode()
                    + (body.isEmpty() ? "" : " " + truncate(body)));
        }
        if (!code.isEmpty() && !"0".equals(code)) {
            // 200 with a non-zero code is a rejection: this is the case a status-code-only sender gets wrong
            return AtomResult.error(ErrorType.THIRD_PART, 40006, "Splunk rejected the event: code " + code
                    + (message.isEmpty() ? "" : " (" + message + ")"));
        }

        context.log("[splunk] event accepted" + (message.isEmpty() ? "" : ": " + message)
                + " (" + payload.length() + " bytes)");
        return AtomResult.success()
                .data("code", code.isEmpty() ? "0" : code)
                .data("text", message)
                .data("bytes", String.valueOf(payload.length()))
                .data("endpoint", endpoint);
    }

    /**
     * The event body: the caller's JSON when given (a literal, or key=value lines), otherwise the build facts the
     * runner already handed us, so the common case needs no configuration at all.
     */
    private static Object eventObject(AtomContext context, String eventParam) {
        if (!eventParam.isEmpty()) {
            try {
                return Json.parse(eventParam);
            } catch (RuntimeException e) {
                Map<String, Object> pairs = new LinkedHashMap<>();
                for (String line : eventParam.split("[,\\n]")) {
                    String trimmed = line.trim();
                    if (trimmed.isEmpty()) {
                        continue;
                    }
                    int split = trimmed.indexOf('=');
                    if (split > 0) {
                        pairs.put(trimmed.substring(0, split).trim(), trimmed.substring(split + 1).trim());
                    }
                }
                if (!pairs.isEmpty()) {
                    return pairs;
                }
                return eventParam;
            }
        }
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("job", context.getParam("atom_build_json", "").isEmpty()
                ? context.getParam("JOB_NAME", "unknown") : buildFact(context, "jobName"));
        facts.put("build", buildFact(context, "number"));
        facts.put("result", buildFact(context, "result"));
        facts.put("url", buildFact(context, "url"));
        facts.put("durationMs", buildFact(context, "duration"));
        facts.put("atom", context.getAtomCode());
        return facts;
    }

    private static String buildFact(AtomContext context, String key) {
        String json = context.getParam("atom_build_json", "");
        if (json.isBlank()) {
            return "";
        }
        try {
            Map<?, ?> map = asMap(json);
            Object value = map.get(key);
            return value == null ? "" : String.valueOf(value);
        } catch (RuntimeException e) {
            return "";
        }
    }

    private static Map<?, ?> asMap(String body) {
        try {
            Object parsed = Json.parse(body == null || body.isBlank() ? "{}" : body);
            return parsed instanceof Map<?, ?> map ? map : Map.of();
        } catch (RuntimeException e) {
            return Map.of();
        }
    }

    private static String text(Map<?, ?> map, String key) {
        Object value = map.get(key);
        return value == null ? "" : String.valueOf(value);
    }

    private static String encode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String truncate(String value) {
        String flat = value.replaceAll("\\s+", " ").trim();
        return flat.length() > 300 ? flat.substring(0, 300) + "…" : flat;
    }
}
