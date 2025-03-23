package edu.thu.benchmark.annotated.entity;

import java.time.LocalDateTime;

/**
 * 命令执行记录实体类
 */
public class CommandExecution {
    private Integer id;
    private String command;
    private String executedBy;
    private LocalDateTime executionTime;
    private String status;
    private String output;

    public CommandExecution() {
    }

    public CommandExecution(String command, String executedBy) {
        this.command = command;
        this.executedBy = executedBy;
        this.executionTime = LocalDateTime.now();
    }

    // Getters and Setters
    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getCommand() {
        return command;
    }

    public void setCommand(String command) {
        this.command = command;
    }

    public String getExecutedBy() {
        return executedBy;
    }

    public void setExecutedBy(String executedBy) {
        this.executedBy = executedBy;
    }

    public LocalDateTime getExecutionTime() {
        return executionTime;
    }

    public void setExecutionTime(LocalDateTime executionTime) {
        this.executionTime = executionTime;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getOutput() {
        return output;
    }

    public void setOutput(String output) {
        this.output = output;
    }

    @Override
    public String toString() {
        return "CommandExecution{" +
                "id=" + id +
                ", command='" + command + '\'' +
                ", executedBy='" + executedBy + '\'' +
                ", executionTime=" + executionTime +
                ", status='" + status + '\'' +
                ", output='" + output + '\'' +
                '}';
    }
}
