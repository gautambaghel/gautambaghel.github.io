# Blog Post Title

*Date: YYYY-MM-DD*

Your introduction paragraph goes here. This should hook the reader and explain what the post is about.

## Section Heading

Your content here. You can use all standard Markdown features:

- Bullet points
- **Bold text**
- *Italic text*
- `inline code`

### Subsection

More detailed content.

```hcl
# Code blocks with syntax highlighting
resource "aws_instance" "example" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
}
```

## Another Section

Continue your article...

### Links and Images

- [Link text](https://example.com)
- ![Alt text](path/to/image.png)

## Conclusion

Wrap up your thoughts here.

---

## How to Add This Blog Post

1. Save this file in the appropriate category folder:
   - `blogs/personal/` - Personal posts
   - `blogs/hashicorp/` - HashiCorp/IBM related posts
   - `blogs/blackduck/` - Black Duck/Synopsys related posts

2. Add an entry to `blogs/blogs.json`:

```json
{
  "id": "unique-post-id",
  "title": "Your Post Title",
  "date": "2025-01-19",
  "category": "personal",
  "excerpt": "A brief description for the blog listing.",
  "external": false,
  "file": "personal/your-file.md",
  "tags": ["tag1", "tag2"]
}
```

3. For external posts (like HashiCorp blog), set `external: true` and provide the `url` instead of `file`.
