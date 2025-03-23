package edu.thu.benchmark.annotated.controller;

import edu.thu.benchmark.annotated.annotation.Vulnerability;
import edu.thu.benchmark.annotated.annotation.VulnerabilityLevel;
import edu.thu.benchmark.annotated.annotation.VulnerabilityType;
import edu.thu.benchmark.annotated.entity.User;
import edu.thu.benchmark.annotated.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

/**
 * 用户控制器
 * 包含XSS和SQL注入漏洞示例
 */
@Controller
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService userService;

    /**
     * 查询所有用户
     */
    @GetMapping
    public String getAllUsers(Model model) {
        List<User> users = userService.getAllUsers();
        model.addAttribute("users", users);
        return "user/list";
    }

    /**
     * 根据ID查询用户
     */
    @GetMapping("/{id}")
    public String getUserById(@PathVariable Integer id, Model model) {
        User user = userService.getUserById(id);
        model.addAttribute("user", user);
        return "user/detail";
    }

    /**
     * 根据用户名查询用户
     * 存在XSS漏洞 - 未对输入输出进行过滤
     */
    @Vulnerability(
            cwe = 79,
            type = VulnerabilityType.XSS,
            description = "直接将用户输入数据未经过滤输出到页面",
            remediation = "使用Spring的th:text或使用HTML编码函数处理输出数据",
            level = VulnerabilityLevel.HIGH
    )
    @GetMapping("/search")
    public void searchByUsername(@RequestParam String username, HttpServletResponse response) throws IOException {
        User user = userService.getUserByUsername(username);
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();

        // 不安全的输出方式，存在XSS漏洞
        out.println("<html><body>");
        if (user != null) {
            out.println("<h2>用户信息:</h2>");
            out.println("<p>你搜索的用户名: " + username + "</p>");
            out.println("<p>ID: " + user.getId() + "</p>");
            out.println("<p>用户名: " + user.getUsername() + "</p>");
            out.println("<p>邮箱: " + user.getEmail() + "</p>");
        } else {
            out.println("<p>未找到用户名为 " + username + " 的用户</p>");
        }
        out.println("</body></html>");
        out.close();
    }

    /**
     * 根据邮箱查询用户
     * 存在SQL注入漏洞 - 直接将用户输入拼接到SQL语句中
     */
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "通过MyBatis的${email}直接将用户输入拼接到SQL语句中",
            remediation = "使用参数化查询 #{email} 替代字符串拼接 ${email}",
            level = VulnerabilityLevel.CRITICAL
    )
    @GetMapping("/findByEmail")
    public String findByEmail(@RequestParam String email, Model model) {
        User user = userService.getUserByEmail(email);
        model.addAttribute("user", user);
        model.addAttribute("email", email);
        return "user/detail";
    }

    /**
     * 根据条件查询用户
     * 存在SQL注入漏洞
     */
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "直接将用户输入作为SQL条件语句",
            remediation = "使用预编译语句和参数化查询，不要直接拼接SQL语句",
            level = VulnerabilityLevel.CRITICAL
    )
    @GetMapping("/findByCondition")
    @ResponseBody
    public List<User> findByCondition(@RequestParam String condition) {
        return userService.findUsersByCondition(condition);
    }

    /**
     * 添加用户表单页面
     */
    @GetMapping("/add")
    public String addUserForm(Model model) {
        model.addAttribute("user", new User());
        return "user/add";
    }

    /**
     * 添加用户处理
     */
    @PostMapping("/add")
    public String addUser(@ModelAttribute User user) {
        userService.insertUser(user);
        return "redirect:/users";
    }

    /**
     * 更新用户信息
     * 存在SQL注入漏洞
     */
    @Vulnerability(
            cwe = 89,
            type = VulnerabilityType.SQL_INJECTION,
            description = "直接将用户输入拼接到SQL更新语句中",
            remediation = "使用参数化更新语句，如PreparedStatement",
            level = VulnerabilityLevel.HIGH
    )
    @PostMapping("/update/{id}")
    @ResponseBody
    public String updateUser(@PathVariable Integer id, @RequestParam String fields) {
        int result = userService.updateUser(id, fields);
        return result > 0 ? "更新成功" : "更新失败";
    }

    /**
     * 删除用户
     */
    @GetMapping("/delete/{id}")
    public String deleteUser(@PathVariable Integer id) {
        userService.deleteUser(id);
        return "redirect:/users";
    }

    /**
     * 反射型XSS漏洞示例
     */
    @Vulnerability(
            cwe = 79,
            type = VulnerabilityType.XSS,
            description = "URL参数未经过滤直接反射到页面",
            remediation = "对输出到HTML页面的内容进行HTML编码",
            level = VulnerabilityLevel.MEDIUM
    )
    @GetMapping("/welcome")
    public void welcome(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();

        // 不安全的输出方式，存在反射型XSS漏洞
        out.println("<html><body>");
        out.println("<h1>欢迎, " + name + "!</h1>");
        out.println("</body></html>");
        out.close();
    }
}
