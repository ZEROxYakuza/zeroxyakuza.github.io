---
layout: page
title: Archives
permalink: /archives/
---

<div class="archive-list">
{% for post in site.posts %}
  <a href="{{ post.url | relative_url }}">
    <span>{{ post.date | date: "%Y-%m-%d" }}</span>
    <strong>{{ post.title }}</strong>
  </a>
{% endfor %}
</div>
