---
layout: page
title: "Reverse Engineering"
permalink: /categories/reverse-engineering/
---

# Reverse Engineering

<div class="post-list">
{% assign posts = site.posts | where_exp: "post", "post.categories contains 'Reverse Engineering'" %}
{% for post in posts %}
  <article class="post-card">
    <div class="post-meta">{{ post.date | date: "%d %b %Y" }}</div>
    <h3><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h3>
    {% if post.description %}<p>{{ post.description }}</p>{% endif %}
  </article>
{% endfor %}
</div>
